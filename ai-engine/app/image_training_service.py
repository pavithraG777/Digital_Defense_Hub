from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings
from app.training_schemas import (
    ImageTrainingRequest,
    TrainingMetric,
)


class TrainingInputError(ValueError):
    pass


@dataclass(frozen=True)
class ImageTrainingResult:
    artifact_path: str
    artifact_sha256: str
    training_record_count: int
    validation_record_count: int
    metrics: list[TrainingMetric]


def validate_image_dataset(
    dataset_path: str,
    dataset_root: Path,
) -> tuple[Path, dict[str, object]]:
    root = dataset_root.resolve()
    candidate = Path(dataset_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise TrainingInputError(
            "dataset path must be inside the configured dataset root"
        ) from error

    if not candidate.is_dir():
        raise TrainingInputError("dataset directory does not exist")

    manifest_path = candidate / "dataset.json"
    if not manifest_path.is_file():
        raise TrainingInputError("dataset.json is required")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TrainingInputError("dataset.json is invalid") from error

    if not isinstance(manifest, dict):
        raise TrainingInputError("dataset.json must contain an object")
    if manifest.get("type") != "image_classification":
        raise TrainingInputError("dataset type must be image_classification")
    if manifest.get("classes") != ["authentic", "manipulated"]:
        raise TrainingInputError(
            "dataset classes must be [authentic, manipulated]"
        )
    image_size = manifest.get("image_size")
    if not isinstance(image_size, int) or image_size < 32 or image_size > 1024:
        raise TrainingInputError("dataset image_size must be between 32 and 1024")
    for class_name in manifest["classes"]:
        if not (candidate / class_name).is_dir():
            raise TrainingInputError(f"missing class directory: {class_name}")
    return candidate, manifest


def train_image_classifier(
    request: ImageTrainingRequest,
    settings: Settings,
) -> ImageTrainingResult:
    dataset_path, manifest = validate_image_dataset(
        request.dataset_path,
        settings.training_dataset_root,
    )
    if request.epochs > settings.training_maximum_epochs:
        raise TrainingInputError("requested epochs exceed configured maximum")

    # Import lazily so health/forensics startup stays available if the optional
    # training stack is misconfigured.
    import torch
    from torch import nn
    from torch.optim import Adam
    from torch.utils.data import DataLoader, random_split
    from torchvision import datasets, transforms

    image_size = int(manifest["image_size"])
    transform = transforms.Compose([
        transforms.Resize((image_size, image_size)),
        transforms.ToTensor(),
        transforms.Normalize((0.5, 0.5, 0.5), (0.5, 0.5, 0.5)),
    ])
    dataset = datasets.ImageFolder(str(dataset_path), transform=transform)
    if dataset.classes != ["authentic", "manipulated"]:
        raise TrainingInputError("ImageFolder classes do not match manifest")
    if len(dataset) > settings.training_maximum_samples:
        raise TrainingInputError("dataset exceeds configured sample maximum")
    if len(dataset) < 4:
        raise TrainingInputError("dataset requires at least four valid images")

    validation_count = max(1, round(len(dataset) * request.validation_percent / 100))
    training_count = len(dataset) - validation_count
    if training_count < 2:
        raise TrainingInputError("dataset leaves too few training images")
    generator = torch.Generator().manual_seed(request.seed)
    training_set, validation_set = random_split(dataset, [training_count, validation_count], generator=generator)
    train_loader = DataLoader(training_set, batch_size=request.batch_size, shuffle=True, num_workers=0)
    validation_loader = DataLoader(validation_set, batch_size=request.batch_size, shuffle=False, num_workers=0)

    device = torch.device("cuda" if settings.media_torch_device == "cuda" and torch.cuda.is_available() else "cpu")
    model = nn.Sequential(
        nn.Conv2d(3, 16, kernel_size=3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
        nn.Conv2d(16, 32, kernel_size=3, padding=1), nn.ReLU(), nn.AdaptiveAvgPool2d((1, 1)),
        nn.Flatten(), nn.Linear(32, 2),
    ).to(device)
    optimizer = Adam(model.parameters(), lr=request.learning_rate)
    criterion = nn.CrossEntropyLoss()
    metrics: list[TrainingMetric] = []
    for epoch in range(1, request.epochs + 1):
        model.train(); train_correct = 0; train_total = 0
        for images, labels in train_loader:
            images, labels = images.to(device), labels.to(device)
            optimizer.zero_grad(); logits = model(images); loss = criterion(logits, labels)
            loss.backward(); optimizer.step()
            train_correct += (logits.argmax(dim=1) == labels).sum().item(); train_total += labels.size(0)
        model.eval(); validation_correct = 0; validation_total = 0
        with torch.no_grad():
            for images, labels in validation_loader:
                logits = model(images.to(device)); labels = labels.to(device)
                validation_correct += (logits.argmax(dim=1) == labels).sum().item(); validation_total += labels.size(0)
        metrics.extend([
            TrainingMetric(metric_name="accuracy", metric_value=100 * train_correct / train_total, dataset_split="TRAIN", epoch_number=epoch),
            TrainingMetric(metric_name="accuracy", metric_value=100 * validation_correct / validation_total, dataset_split="VALIDATION", epoch_number=epoch),
        ])

    artifact_dir = (settings.training_artifact_root / str(request.organization_id)).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{request.training_job_id}.pth"
    temporary_path = artifact_path.with_suffix(".pth.tmp")
    torch.save({"format_version": "1.0", "architecture": "ddh_cnn_v1", "classes": dataset.classes, "image_size": image_size, "state_dict": model.cpu().state_dict()}, temporary_path)
    os.replace(temporary_path, artifact_path)
    digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    return ImageTrainingResult(str(artifact_path), digest, training_count, validation_count, metrics)
