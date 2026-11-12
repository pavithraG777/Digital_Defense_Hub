"""Read-only category audit for the currently selected specialized image models."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import torch
from PIL import Image
from torch import nn
from torch.utils.data import DataLoader, Dataset
from torchvision import transforms
from torchvision.models import mobilenet_v3_small


ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "datasets" / "unified-manipulation-detection-v7-20000"
WHOLE_MODEL = ROOT / "data" / "colab-trained" / "ensemble-v4" / "ddh-whole-image-ai-v4.pth"
FACE_MODEL = ROOT / "data" / "colab-trained" / "ensemble-v2" / "ddh-face-swap-v2.pth"
UNIFIED_MODEL = ROOT / "data" / "colab-trained" / "v6" / "ddh-unified-v6-mobilenet-v3-small.pth"
WHOLE_THRESHOLD = 0.59
FACE_THRESHOLD = 0.53
UNIFIED_THRESHOLD = 0.50
FACE_CATEGORIES = {"face_swap", "faceforensics_real"}


class Images(Dataset):
    def __init__(self, rows: list[dict[str, str]]) -> None:
        self.rows = rows
        self.transform = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize((.485, .456, .406), (.229, .224, .225)),
        ])

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int):
        row = self.rows[index]
        with Image.open(DATASET / row["relative_path"]) as image:
            tensor = self.transform(image.convert("RGB"))
        return tensor, index


def load_model(path: Path):
    checkpoint = torch.load(path, map_location="cpu", weights_only=True)
    assert checkpoint["format_version"] == "1.0"
    assert checkpoint["classes"] == ["authentic", "deepfake"]
    model = mobilenet_v3_small(weights=None)
    model.classifier[-1] = nn.Linear(model.classifier[-1].in_features, 2)
    model.load_state_dict(checkpoint["state_dict"], strict=True)
    model.eval()
    return model, checkpoint


def infer(model, rows: list[dict[str, str]]) -> list[float]:
    probabilities = [0.0] * len(rows)
    loader = DataLoader(Images(rows), batch_size=32, shuffle=False, num_workers=2)
    with torch.inference_mode():
        for images, indices in loader:
            scores = torch.softmax(model(images), dim=1)[:, 1].tolist()
            for index, score in zip(indices.tolist(), scores):
                probabilities[index] = score
    return probabilities


def category_result(rows: list[dict], field: str, threshold: float) -> dict:
    labels = [row["class"] == "deepfake" for row in rows]
    predictions = [row[field] >= threshold for row in rows]
    correct = sum(actual == predicted for actual, predicted in zip(labels, predictions))
    positives = sum(labels)
    negatives = len(labels) - positives
    tp = sum(actual and predicted for actual, predicted in zip(labels, predictions))
    tn = sum(not actual and not predicted for actual, predicted in zip(labels, predictions))
    return {
        "samples": len(rows),
        "accuracy": correct / len(rows),
        "deepfake_recall": tp / positives if positives else None,
        "authentic_specificity": tn / negatives if negatives else None,
        "mean_deepfake_score": sum(row[field] for row in rows) / len(rows),
    }


def main() -> None:
    torch.set_num_threads(2)
    rows = [
        row for row in csv.DictReader((DATASET / "provenance.csv").open(encoding="utf-8"))
        if row["split"] == "test"
    ]
    whole_model, whole_checkpoint = load_model(WHOLE_MODEL)
    face_model, face_checkpoint = load_model(FACE_MODEL)
    unified_model, unified_checkpoint = load_model(UNIFIED_MODEL)
    whole_scores = infer(whole_model, rows)
    unified_scores = infer(unified_model, rows)
    face_positions = [index for index, row in enumerate(rows) if row["category"] in FACE_CATEGORIES]
    face_rows = [rows[index] for index in face_positions]
    face_scores = infer(face_model, face_rows)

    predictions = []
    face_by_position = dict(zip(face_positions, face_scores))
    for index, (row, whole_score, unified_score) in enumerate(zip(rows, whole_scores, unified_scores)):
        face_score = face_by_position.get(index)
        applicable_face = face_score is not None
        ensemble_fake = whole_score >= WHOLE_THRESHOLD or (
            applicable_face and face_score >= FACE_THRESHOLD
        ) or unified_score >= UNIFIED_THRESHOLD
        predictions.append({
            **row,
            "whole_score": whole_score,
            "face_score": face_score,
            "unified_score": unified_score,
            "ensemble_score": max(whole_score, face_score or 0.0, unified_score),
            "ensemble_fake": ensemble_fake,
        })

    by_category = defaultdict(list)
    for row in predictions:
        by_category[row["category"]].append(row)
    categories = {}
    for category, category_rows in sorted(by_category.items()):
        labels = [row["class"] == "deepfake" for row in category_rows]
        predicted = [row["ensemble_fake"] for row in category_rows]
        positives = sum(labels); negatives = len(labels) - positives
        tp = sum(a and p for a, p in zip(labels, predicted))
        tn = sum(not a and not p for a, p in zip(labels, predicted))
        categories[category] = {
            "samples": len(category_rows),
            "ensemble_accuracy": sum(a == p for a, p in zip(labels, predicted)) / len(labels),
            "deepfake_recall": tp / positives if positives else None,
            "authentic_specificity": tn / negatives if negatives else None,
            "whole_detector": category_result(category_rows, "whole_score", WHOLE_THRESHOLD),
            "unified_v6_detector": category_result(category_rows, "unified_score", UNIFIED_THRESHOLD),
            "face_detector_applicable": category in FACE_CATEGORIES,
        }
        if category in FACE_CATEGORIES:
            categories[category]["face_detector"] = category_result(
                category_rows, "face_score", FACE_THRESHOLD
            )

    unified_threshold_sweep = {}
    for threshold in (.50, .60, .70, .80, .85, .90, .95):
        unified_threshold_sweep[f"{threshold:.2f}"] = {
            category: category_result(category_rows, "unified_score", threshold)
            for category, category_rows in sorted(by_category.items())
        }

    report = {
        "models": {
            "whole_image_v4": {
                "path": str(WHOLE_MODEL),
                "sha256": hashlib.sha256(WHOLE_MODEL.read_bytes()).hexdigest(),
                "threshold": WHOLE_THRESHOLD,
                "checkpoint_scope": whole_checkpoint.get("detector_scope"),
            },
            "face_swap_v2": {
                "path": str(FACE_MODEL),
                "sha256": hashlib.sha256(FACE_MODEL.read_bytes()).hexdigest(),
                "threshold": FACE_THRESHOLD,
                "checkpoint_scope": face_checkpoint.get("detector_scope"),
            },
            "unified_v6": {
                "path": str(UNIFIED_MODEL),
                "sha256": hashlib.sha256(UNIFIED_MODEL.read_bytes()).hexdigest(),
                "threshold": UNIFIED_THRESHOLD,
                "checkpoint_scope": unified_checkpoint.get("detector_scope"),
            },
        },
        "dataset": str(DATASET),
        "test_samples": len(rows),
        "categories": categories,
        "unified_v6_threshold_sweep": unified_threshold_sweep,
        "unsupported_or_unevaluated": {
            "morphing": "No separately labelled morphing source or holdout was found.",
            "snapchat_filtered": "Present only in V7 training; no V7 validation/test records.",
            "remini_enhanced": "Present only in V7 training; no V7 validation/test records.",
        },
        "limitations": [
            "This is a checkpoint/category audit, not a new independent benchmark.",
            "Face applicability is inferred from the prepared category; live face detection/routing is not replayed.",
            "The OR decision is a coverage audit and may differ from the production weighted ensemble verdict.",
            "The V7 modern-AI test source predates the V4 source-isolated holdout.",
        ],
    }
    output = ROOT / "data" / "diagnostics"
    output.mkdir(exist_ok=True)
    (output / "deepfake-ensemble-category-audit.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
