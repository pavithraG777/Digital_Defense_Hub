from __future__ import annotations

import copy
import csv
import hashlib
import json
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings
from app.training_schemas import ImageTrainingRequest, TrainingMetric


class TrainingInputError(ValueError):
    pass


@dataclass(frozen=True)
class ImageTrainingResult:
    artifact_path: str
    artifact_sha256: str
    training_record_count: int
    validation_record_count: int
    test_record_count: int
    metrics: list[TrainingMetric]


def validate_image_dataset(dataset_path: str, dataset_root: Path) -> tuple[Path, dict[str, object]]:
    root, candidate = dataset_root.resolve(), Path(dataset_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise TrainingInputError("dataset path must be inside the configured dataset root") from error
    if not candidate.is_dir():
        raise TrainingInputError("dataset directory does not exist")
    try:
        manifest = json.loads((candidate / "dataset.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TrainingInputError("dataset.json is required and must be valid") from error
    if not isinstance(manifest, dict) or manifest.get("type") != "image_classification":
        raise TrainingInputError("dataset type must be image_classification")
    classes = manifest.get("classes")
    if not isinstance(classes, list) or len(classes) != 2 or not all(isinstance(x, str) and x.strip() for x in classes):
        raise TrainingInputError("dataset classes must contain exactly two class names")
    manifest["classes"] = [x.strip() for x in classes]
    size = manifest.get("image_size")
    if not isinstance(size, int) or not 32 <= size <= 1024:
        raise TrainingInputError("dataset image_size must be between 32 and 1024")
    if any(not (candidate / name).is_dir() for name in manifest["classes"]):
        raise TrainingInputError("one or more class directories are missing")
    return candidate, manifest


def binary_classification_metrics(labels: list[int], predictions: list[int]) -> dict[str, float]:
    if not labels or len(labels) != len(predictions):
        return {}
    tp = sum(a == 1 and p == 1 for a, p in zip(labels, predictions, strict=True))
    tn = sum(a == 0 and p == 0 for a, p in zip(labels, predictions, strict=True))
    fp = sum(a == 0 and p == 1 for a, p in zip(labels, predictions, strict=True))
    fn = sum(a == 1 and p == 0 for a, p in zip(labels, predictions, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"accuracy": 100 * (tp + tn) / len(labels), "precision": 100 * precision,
            "recall": 100 * recall, "specificity": 100 * specificity, "f1": 100 * f1,
            "confusion_tp": float(tp), "confusion_tn": float(tn),
            "confusion_fp": float(fp), "confusion_fn": float(fn)}


def _stratified_indices(targets, validation_percent, test_percent, seed):
    import torch
    groups = defaultdict(list)
    for index, target in enumerate(targets):
        groups[int(target)].append(index)
    generator = torch.Generator().manual_seed(seed)
    train, validation, test = [], [], []
    for indices in groups.values():
        shuffled = [indices[i] for i in torch.randperm(len(indices), generator=generator).tolist()]
        v_count = max(1, round(len(indices) * validation_percent / 100))
        t_count = round(len(indices) * test_percent / 100)
        validation += shuffled[:v_count]
        test += shuffled[v_count:v_count + t_count]
        train += shuffled[v_count + t_count:]
    return train, validation, test


def _group_stratified_indices(path, indexed, manifest, validation_percent, test_percent, seed):
    import random
    manifest_name = manifest.get("group_manifest")
    if not isinstance(manifest_name, str) or not manifest_name:
        return _stratified_indices(indexed.targets, validation_percent, test_percent, seed)
    rows = {}
    with (path / manifest_name).open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            rows[row["relative_path"].replace("\\", "/")] = row["source_group"]
    grouped = defaultdict(list)
    for index, (filename, _) in enumerate(indexed.samples):
        relative = Path(filename).relative_to(path).as_posix()
        if relative not in rows:
            raise TrainingInputError(f"group manifest is missing image: {relative}")
        grouped[rows[relative]].append(index)
    train_only_names = {
        name for name in grouped if name.startswith("train-only:")
    }
    group_names = sorted(name for name in grouped if name not in train_only_names)
    if not group_names:
        raise TrainingInputError("group manifest leaves no validation/test candidate groups")
    random.Random(seed).shuffle(group_names)
    validation_groups = max(1, round(len(group_names) * validation_percent / 100))
    test_groups = round(len(group_names) * test_percent / 100)
    validation_names = set(group_names[:validation_groups])
    test_names = set(group_names[validation_groups:validation_groups + test_groups])
    train, validation, test = [], [], []
    for group, indices in grouped.items():
        (validation if group in validation_names else test if group in test_names else train).extend(indices)
    return train, validation, test


def _evaluate(model, loader, device):
    import torch
    actual, predicted = [], []
    model.eval()
    with torch.no_grad():
        for images, labels in loader:
            actual += labels.tolist()
            predicted += model(images.to(device)).argmax(1).cpu().tolist()
    return actual, predicted


def _rows(values, split, epoch):
    return [TrainingMetric(metric_name=k, metric_value=v, dataset_split=split, epoch_number=epoch) for k, v in values.items()]


def train_image_classifier(request: ImageTrainingRequest, settings: Settings) -> ImageTrainingResult:
    path, manifest = validate_image_dataset(request.dataset_path, settings.training_dataset_root)
    if request.epochs > settings.training_maximum_epochs:
        raise TrainingInputError("requested epochs exceed configured maximum")
    if request.validation_percent + request.test_percent > 80:
        raise TrainingInputError("validation and test percentages leave too few training images")
    import torch
    from torch import nn
    from torch.optim import AdamW
    from torch.optim.lr_scheduler import ReduceLROnPlateau
    from torch.utils.data import DataLoader, Subset, WeightedRandomSampler
    from torchvision import datasets, transforms
    from torchvision.models import MobileNet_V3_Small_Weights, mobilenet_v3_small

    size = int(manifest["image_size"])
    normalize = transforms.Normalize((.485, .456, .406), (.229, .224, .225))
    train_transform = transforms.Compose([transforms.Resize((size + 16, size + 16)),
        transforms.RandomResizedCrop(size, scale=(.82, 1.0)), transforms.RandomHorizontalFlip(),
        transforms.RandomApply([transforms.ColorJitter(.15, .15, .1)], p=.5),
        transforms.RandomApply([transforms.GaussianBlur(3)], p=.15), transforms.ToTensor(), normalize])
    eval_transform = transforms.Compose([transforms.Resize((size, size)), transforms.ToTensor(), normalize])
    indexed = datasets.ImageFolder(str(path))
    if indexed.classes != manifest["classes"]:
        raise TrainingInputError("ImageFolder classes do not match manifest")
    if len(indexed) > settings.training_maximum_samples:
        raise TrainingInputError("dataset exceeds configured sample maximum")
    train_idx, val_idx, test_idx = _group_stratified_indices(path, indexed, manifest, request.validation_percent, request.test_percent, request.seed)
    if len(train_idx) < 2:
        raise TrainingInputError("dataset leaves too few training images")
    train_data = datasets.ImageFolder(str(path), transform=train_transform)
    eval_data = datasets.ImageFolder(str(path), transform=eval_transform)
    counts = [sum(indexed.targets[i] == c for i in train_idx) for c in range(2)]
    weights = [1 / counts[indexed.targets[i]] for i in train_idx]
    sampler = WeightedRandomSampler(weights, len(weights), generator=torch.Generator().manual_seed(request.seed))
    train_loader = DataLoader(Subset(train_data, train_idx), request.batch_size, sampler=sampler, num_workers=0)
    val_loader = DataLoader(Subset(eval_data, val_idx), request.batch_size, num_workers=0)
    test_loader = DataLoader(Subset(eval_data, test_idx), request.batch_size, num_workers=0) if test_idx else None

    device = torch.device("cuda" if settings.media_torch_device == "cuda" and torch.cuda.is_available() else "cpu")
    pretrained = True
    try:
        model = mobilenet_v3_small(weights=MobileNet_V3_Small_Weights.DEFAULT)
    except Exception:
        pretrained, model = False, mobilenet_v3_small(weights=None)
    model.classifier[-1] = nn.Linear(model.classifier[-1].in_features, 2)
    model.to(device)
    optimizer = AdamW(model.parameters(), request.learning_rate, weight_decay=.01)
    class_weights = torch.tensor(
        [1.0, request.deepfake_class_weight],
        dtype=torch.float32,
        device=device,
    )
    scheduler = ReduceLROnPlateau(optimizer, mode="max", patience=1)
    criterion = nn.CrossEntropyLoss(
        weight=class_weights,
        label_smoothing=.05,
    )
    metrics, best_state, best_accuracy, best_epoch, stale = [], copy.deepcopy(model.state_dict()), -1.0, 1, 0
    for epoch in range(1, request.epochs + 1):
        model.train(); actual, predicted = [], []
        for images, labels in train_loader:
            images, labels = images.to(device), labels.to(device)
            optimizer.zero_grad(set_to_none=True); logits = model(images); criterion(logits, labels).backward(); optimizer.step()
            actual += labels.cpu().tolist(); predicted += logits.argmax(1).cpu().tolist()
        train_values = binary_classification_metrics(actual, predicted)
        val_actual, val_predicted = _evaluate(model, val_loader, device)
        val_values = binary_classification_metrics(val_actual, val_predicted)
        metrics += _rows({"accuracy": train_values["accuracy"]}, "TRAIN", epoch) + _rows(val_values, "VALIDATION", epoch)
        selection_score = val_values[request.selection_metric]
        scheduler.step(selection_score)
        if selection_score > best_accuracy:
            best_accuracy, best_epoch, best_state, stale = selection_score, epoch, copy.deepcopy(model.state_dict()), 0
        else:
            stale += 1
            if stale >= 3: break
    model.load_state_dict(best_state)
    if test_loader:
        actual, predicted = _evaluate(model, test_loader, device)
        metrics += _rows(binary_classification_metrics(actual, predicted), "TEST", best_epoch)
    metrics += _rows({
        "best_epoch": float(best_epoch),
        "best_selection_score": float(best_accuracy),
        "deepfake_class_weight": request.deepfake_class_weight,
    }, "VALIDATION", best_epoch)
    metrics += _rows({"pretrained_weights": float(pretrained)}, "TRAIN", best_epoch)
    artifact_dir = (settings.training_artifact_root / str(request.organization_id)).resolve(); artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact = artifact_dir / f"{request.training_job_id}.pth"; temporary = artifact.with_suffix(".pth.tmp")
    torch.save({"format_version": "1.0", "architecture": "mobilenet_v3_small_forensics_v1",
                "classes": indexed.classes, "image_size": size, "pretrained_weights": pretrained,
                "detector_scope": request.detector_scope,
                "best_epoch": best_epoch,
                "selection_metric": request.selection_metric,
                "deepfake_class_weight": request.deepfake_class_weight,
                "state_dict": model.cpu().state_dict()}, temporary)
    os.replace(temporary, artifact)
    return ImageTrainingResult(str(artifact), hashlib.sha256(artifact.read_bytes()).hexdigest(), len(train_idx), len(val_idx), len(test_idx), metrics)
