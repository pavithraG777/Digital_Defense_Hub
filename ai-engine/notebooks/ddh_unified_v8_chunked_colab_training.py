"""Resumable Google Colab trainer for DDH Unified Deepfake V8.

Upload the prepared dataset as ``MyDrive/DDH/unified-deepfake-v8-all-sources.zip``.
Each execution trains only PARTS_PER_RUN deterministic parts and persists the
model, optimizer and exact cursor to Drive. Re-run the same Colab cell until
``training-complete.json`` appears. The final PTH is compatible with DDH.
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import shutil
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import torch
from PIL import Image
from sklearn.metrics import balanced_accuracy_score, precision_recall_fscore_support
from torch import nn
from torch.utils.data import DataLoader, Dataset
from torchvision import transforms
from torchvision.models import MobileNet_V3_Small_Weights, mobilenet_v3_small

DRIVE = Path("/content/drive/MyDrive/DDH")
ARCHIVE = DRIVE / "unified-deepfake-v8-all-sources.zip"
WORK = Path("/content/ddh-v8")
OUTPUT = DRIVE / "unified-v8-training-output"
STATE = OUTPUT / "resume-state.pth"
FINAL = OUTPUT / "ddh-unified-deepfake-v8.pth"
METRICS = OUTPUT / "training-metrics.json"
COMPLETE = OUTPUT / "training-complete.json"

IMAGE_SIZE = 224
BATCH_SIZE = 64
EPOCHS = 10
PART_SIZE = 2000
PARTS_PER_RUN = 2
LEARNING_RATE = 1e-4
SEED = 20260918


class ManifestDataset(Dataset):
    def __init__(self, root: Path, rows: list[dict[str, str]], transform) -> None:
        self.root, self.rows, self.transform = root, rows, transform

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int):
        row = self.rows[index]
        with Image.open(self.root / row["relative_path"]) as image:
            value = self.transform(image.convert("RGB"))
        return value, 1 if row.get("class", row.get("label")) == "deepfake" else 0


def seed_everything() -> None:
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
    if torch.cuda.is_available(): torch.cuda.manual_seed_all(SEED)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare_dataset() -> tuple[Path, dict, list[dict[str, str]]]:
    if not ARCHIVE.is_file():
        raise FileNotFoundError(f"Upload the V8 dataset archive to {ARCHIVE}")
    print(f"Found dataset archive: {ARCHIVE} ({ARCHIVE.stat().st_size / 1024**3:.2f} GiB)", flush=True)
    print("Verifying archive SHA-256; a 7 GiB Drive file can take several minutes...", flush=True)
    archive_hash = file_sha256(ARCHIVE)
    marker = WORK / ".archive-sha256"
    if not marker.is_file() or marker.read_text().strip() != archive_hash:
        print("Extracting the dataset into the Colab runtime...", flush=True)
        if WORK.exists(): shutil.rmtree(WORK)
        WORK.mkdir(parents=True)
        with zipfile.ZipFile(ARCHIVE) as bundle: bundle.extractall(WORK)
        marker.write_text(archive_hash)
        print("Dataset extraction complete.", flush=True)
    manifests = list(WORK.rglob("dataset.json"))
    if len(manifests) != 1: raise RuntimeError("Archive must contain exactly one dataset.json")
    root = manifests[0].parent
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    provenance = root / manifest.get("provenance_manifest", "provenance.csv")
    rows = list(csv.DictReader(provenance.open(encoding="utf-8", newline="")))
    if len(rows) != int(manifest["record_count"]): raise RuntimeError("Manifest record count mismatch")
    missing = [row["relative_path"] for row in rows if not (root / row["relative_path"]).is_file()]
    if missing: raise RuntimeError(f"Dataset has {len(missing)} missing image files")
    return root, manifest, rows


def model_and_transforms():
    weights = MobileNet_V3_Small_Weights.DEFAULT
    model = mobilenet_v3_small(weights=weights)
    model.classifier[-1] = nn.Linear(model.classifier[-1].in_features, 2)
    train_transform = transforms.Compose([
        transforms.RandomResizedCrop(IMAGE_SIZE, scale=(0.75, 1.0)),
        transforms.RandomHorizontalFlip(), transforms.ColorJitter(0.15, 0.15, 0.15, 0.05),
        transforms.ToTensor(), transforms.Normalize(weights.transforms().mean, weights.transforms().std),
    ])
    eval_transform = transforms.Compose([
        transforms.Resize(256), transforms.CenterCrop(IMAGE_SIZE), transforms.ToTensor(),
        transforms.Normalize(weights.transforms().mean, weights.transforms().std),
    ])
    return model, train_transform, eval_transform


def deterministic_parts(rows: list[dict[str, str]]) -> list[list[dict[str, str]]]:
    ordered = sorted(rows, key=lambda row: hashlib.sha256(f"{SEED}:{row['relative_path']}".encode()).hexdigest())
    return [ordered[index:index + PART_SIZE] for index in range(0, len(ordered), PART_SIZE)]


@torch.inference_mode()
def evaluate(model, root, rows, transform, device) -> dict[str, float]:
    model.eval(); labels, predictions = [], []
    loader = DataLoader(ManifestDataset(root, rows, transform), batch_size=BATCH_SIZE, shuffle=False, num_workers=2)
    for images, targets in loader:
        predicted = model(images.to(device)).argmax(1).cpu().tolist()
        labels.extend(targets.tolist()); predictions.extend(predicted)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary", zero_division=0)
    specificity = sum(p == 0 and y == 0 for y, p in zip(labels, predictions)) / max(1, sum(y == 0 for y in labels))
    return {"balanced_accuracy": balanced_accuracy_score(labels, predictions), "precision": precision, "recall": recall, "specificity": specificity, "f1": f1}


def main() -> None:
    seed_everything(); OUTPUT.mkdir(parents=True, exist_ok=True)
    print(f"Persistent output: {OUTPUT}", flush=True)
    root, manifest, rows = prepare_dataset()
    counts = Counter(row.get("split", "train").lower() for row in rows)
    print(json.dumps({"records": len(rows), "splits": counts, "classes": manifest.get("class_distribution")}, indent=2, default=dict))
    train_rows = [row for row in rows if row.get("split", "train").lower() == "train"]
    validation_rows = [row for row in rows if row.get("split", "train").lower() == "validation"]
    test_rows = [row for row in rows if row.get("split", "train").lower() == "test"]
    if not train_rows or not validation_rows or not test_rows: raise RuntimeError("V8 requires explicit train, validation and test splits")
    parts = deterministic_parts(train_rows)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type != "cuda": raise RuntimeError("Select a Colab GPU runtime")
    model, train_transform, eval_transform = model_and_transforms(); model.to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-4)
    state = {"epoch": 0, "part": 0, "history": []}
    if STATE.is_file():
        print(f"Resuming from {STATE}", flush=True)
        saved = torch.load(STATE, map_location="cpu", weights_only=True)
        model.load_state_dict(saved["state_dict"], strict=True); optimizer.load_state_dict(saved["optimizer_state"])
        state = {"epoch": int(saved["epoch"]), "part": int(saved["part"]), "history": saved.get("history", [])}
    criterion = nn.CrossEntropyLoss(); processed = 0
    while state["epoch"] < EPOCHS and processed < PARTS_PER_RUN:
        part_rows = parts[state["part"]]
        print(f"Training epoch {state['epoch'] + 1}/{EPOCHS}, part {state['part'] + 1}/{len(parts)}, records={len(part_rows)}", flush=True)
        generator = torch.Generator().manual_seed(SEED + state["epoch"] * len(parts) + state["part"])
        loader = DataLoader(ManifestDataset(root, part_rows, train_transform), batch_size=BATCH_SIZE, shuffle=True, generator=generator, num_workers=2, pin_memory=True)
        model.train(); loss_sum = 0.0
        for images, targets in loader:
            optimizer.zero_grad(set_to_none=True); loss = criterion(model(images.to(device)), targets.to(device)); loss.backward(); optimizer.step()
            loss_sum += float(loss.item()) * len(targets)
        state["history"].append({"epoch": state["epoch"] + 1, "part": state["part"] + 1, "records": len(part_rows), "loss": loss_sum / len(part_rows)})
        state["part"] += 1; processed += 1
        if state["part"] == len(parts):
            state["history"][-1]["validation"] = evaluate(model, root, validation_rows, eval_transform, device)
            state["epoch"] += 1; state["part"] = 0
        torch.save({"format_version": "1.0-resume", "architecture": "mobilenet_v3_small_forensics_v1", "classes": ["authentic", "deepfake"], "image_size": IMAGE_SIZE, "dataset_name": manifest.get("name"), "dataset_record_count": len(rows), "state_dict": model.state_dict(), "optimizer_state": optimizer.state_dict(), **state}, STATE)
        METRICS.write_text(json.dumps(state["history"], indent=2) + "\n", encoding="utf-8")
        print(f"saved epoch={state['epoch'] + 1} next_part={state['part'] + 1}/{len(parts)}")
    if state["epoch"] == EPOCHS:
        final_test = evaluate(model, root, test_rows, eval_transform, device)
        torch.save({"format_version": "1.0", "architecture": "mobilenet_v3_small_forensics_v1", "classes": ["authentic", "deepfake"], "image_size": IMAGE_SIZE, "dataset_name": manifest.get("name"), "dataset_record_count": len(rows), "state_dict": model.state_dict()}, FINAL)
        COMPLETE.write_text(json.dumps({"model": str(FINAL), "records": len(rows), "epochs": EPOCHS, "test": final_test}, indent=2) + "\n", encoding="utf-8")
        print(COMPLETE.read_text())
    else:
        print("Run the same Colab cell again to continue from the saved cursor.")


if __name__ == "__main__": main()
