#!/usr/bin/env python
"""Evaluate an approved DDH image model on a provenance-tracked holdout."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import cv2

AI_ENGINE_ROOT = Path(__file__).resolve().parents[1]
if str(AI_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE_ROOT))

from app.media_forensics_schemas import ModelExecutionSpecification
from app.media_model_runner import MediaModelRunner


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def metrics(expected: list[int], predicted: list[int]) -> dict[str, float | int]:
    tp = sum(a == 1 and b == 1 for a, b in zip(expected, predicted))
    tn = sum(a == 0 and b == 0 for a, b in zip(expected, predicted))
    fp = sum(a == 0 and b == 1 for a, b in zip(expected, predicted))
    fn = sum(a == 1 and b == 0 for a, b in zip(expected, predicted))
    total = max(1, len(expected))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    specificity = tn / max(1, tn + fp)
    return {
        "count": len(expected), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy_percent": round((tp + tn) * 100 / total, 4),
        "precision_percent": round(precision * 100, 4),
        "recall_percent": round(recall * 100, 4),
        "specificity_percent": round(specificity * 100, 4),
        "f1_percent": round(2 * precision * recall * 100 / max(1e-12, precision + recall), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("holdout", type=Path)
    parser.add_argument("model", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--threshold", type=float, default=50.0)
    parser.add_argument(
        "--region",
        choices=["whole", "face", "face-context-v2"],
        default="whole",
    )
    parser.add_argument("--face-cascade", type=Path)
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise FileExistsError(f"Evaluation output is not empty: {args.output}")
    args.output.mkdir(parents=True, exist_ok=True)

    model_hash = sha256(args.model)
    model_configuration = {
        "input_width": 224, "input_height": 224, "channel_order": "RGB",
        "pixel_scale": 255.0, "mean": [0.485, 0.456, 0.406],
        "std": [0.229, 0.224, 0.225], "output_mode": "MULTICLASS_LOGITS",
        "deepfake_class_index": 1,
    }
    if args.region == "face-context-v2":
        model_configuration.update({
            "preprocessing": "EARLY_WINDOW_FACE_CONTEXT_CROP_V2",
            "context_scale": 2.35,
        })
    specification = ModelExecutionSpecification(
        model_name="MOBILENET_V3_SMALL_FORENSICS",
        model_version="APPROVED_FF8E3F16",
        model_format="PTH",
        model_file_path=str(args.model.resolve()),
        model_file_hash=model_hash,
        confidence_threshold=args.threshold,
        configuration=model_configuration,
    )
    runner = MediaModelRunner()
    face_detector = None
    if args.region == "face":
        cascade_path = args.face_cascade or Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml"
        face_detector = cv2.CascadeClassifier(str(cascade_path))
        if face_detector.empty():
            raise RuntimeError(f"Unable to load face cascade: {cascade_path}")
    manifest_rows = list(csv.DictReader((args.holdout / "manifest.csv").open(encoding="utf-8")))
    predictions: list[dict[str, object]] = []
    per_video: dict[str, list[float]] = defaultdict(list)
    video_labels: dict[str, int] = {}
    for row in manifest_rows:
        image_path = args.holdout / row["relative_path"]
        image = cv2.imread(str(image_path), cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError(f"Unable to decode holdout image: {image_path}")
        face_detected = False
        if face_detector is not None:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            faces = face_detector.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(64, 64))
            if len(faces):
                x, y, width, height = max(faces, key=lambda value: int(value[2]) * int(value[3]))
                margin = int(max(width, height) * 0.25)
                left, top = max(0, x - margin), max(0, y - margin)
                right, bottom = min(image.shape[1], x + width + margin), min(image.shape[0], y + height + margin)
                image = image[top:bottom, left:right]
                face_detected = True
        result = runner.run_image(specification, image)
        expected = 1 if row["label"] == "deepfake" else 0
        predicted = 1 if result.deepfake_probability >= args.threshold else 0
        per_video[row["source_video"]].append(result.deepfake_probability)
        video_labels[row["source_video"]] = expected
        predictions.append({
            **row,
            "expected_class": "deepfake" if expected else "authentic",
            "predicted_class": "deepfake" if predicted else "authentic",
            "deepfake_probability": f"{result.deepfake_probability:.4f}",
            "authenticity_probability": f"{result.authenticity_probability:.4f}",
            "correct": expected == predicted,
            "evaluation_region": args.region,
            "face_detected": face_detected,
        })

    video_rows: list[dict[str, object]] = []
    for source_video, probabilities in sorted(per_video.items()):
        mean_probability = sum(probabilities) / len(probabilities)
        expected = video_labels[source_video]
        predicted = 1 if mean_probability >= args.threshold else 0
        video_rows.append({
            "source_video": source_video,
            "expected_class": "deepfake" if expected else "authentic",
            "predicted_class": "deepfake" if predicted else "authentic",
            "mean_deepfake_probability": f"{mean_probability:.4f}",
            "frame_count": len(probabilities),
            "correct": expected == predicted,
        })

    with (args.output / "frame_predictions.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(predictions[0]))
        writer.writeheader(); writer.writerows(predictions)
    with (args.output / "video_predictions.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(video_rows[0]))
        writer.writeheader(); writer.writerows(video_rows)

    frame_expected = [1 if row["expected_class"] == "deepfake" else 0 for row in predictions]
    frame_predicted = [1 if row["predicted_class"] == "deepfake" else 0 for row in predictions]
    video_expected = [1 if row["expected_class"] == "deepfake" else 0 for row in video_rows]
    video_predicted = [1 if row["predicted_class"] == "deepfake" else 0 for row in video_rows]
    if args.region == "face":
        face_detection = {
            "mode": "EVALUATOR_MANAGED",
            "detected_frames": sum(bool(row["face_detected"]) for row in predictions),
            "fallback_whole_frames": sum(not bool(row["face_detected"]) for row in predictions),
        }
    elif args.region == "face-context-v2":
        face_detection = {
            "mode": "MODEL_RUNNER_MANAGED",
            "preprocessing": "EARLY_WINDOW_FACE_CONTEXT_CROP_V2",
            "context_scale": 2.35,
        }
    else:
        face_detection = {"mode": "DISABLED"}

    report = {
        "evaluation_type": "EXTERNAL_UNSEEN_FACEFORENSICS_HOLDOUT",
        "model_path": str(args.model.resolve()), "model_sha256": model_hash,
        "decision_threshold_percent": args.threshold,
        "evaluation_region": args.region,
        "face_detection": face_detection,
        "frame_level": metrics(frame_expected, frame_predicted),
        "video_level_mean_probability": metrics(video_expected, video_predicted),
        "limitations": [
            "The holdout contains 20 c40-compressed videos from five matched source groups.",
            "Frames from a video are correlated; video-level metrics are the primary result.",
            "This evaluation does not estimate performance on non-face manipulations.",
        ],
    }
    (args.output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
