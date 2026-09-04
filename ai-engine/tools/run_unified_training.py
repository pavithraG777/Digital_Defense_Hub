#!/usr/bin/env python
"""Train the unified manipulated-image detector with the approved split."""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parents[1]))

from app.config import get_settings
from app.image_training_service import train_image_classifier, validate_image_dataset
from app.training_schemas import ImageTrainingRequest


def main() -> None:
    settings = get_settings()
    dataset_path = "E:/Cyber-Security-Platform/datasets/unified-manipulation-detection-v5-10000"
    path, manifest = validate_image_dataset(dataset_path, settings.training_dataset_root)
    print(f"validated records={manifest['record_count']} group_manifest={manifest.get('group_manifest')}", flush=True)
    request = ImageTrainingRequest(
        request_id=uuid4(),
        training_job_id=uuid4(),
        organization_id=uuid4(),
        dataset_version_id=uuid4(),
        dataset_path=str(path),
        model_code="unified-manipulated-image-detector",
        detector_scope="DEEPFAKE_IMAGE_DETECTION",
        epochs=10,
        batch_size=8,
        learning_rate=0.0001,
        deepfake_class_weight=1.0,
        selection_metric="f1",
        validation_percent=15,
        test_percent=15,
        seed=42,
    )
    result = train_image_classifier(request, settings)
    print(f"artifact={result.artifact_path}", flush=True)
    print(f"counts train={result.training_record_count} validation={result.validation_record_count} test={result.test_record_count}", flush=True)
    for metric in result.metrics:
        if metric.dataset_split in {"VALIDATION", "TEST"} and metric.metric_name in {"accuracy", "precision", "recall", "specificity", "f1"}:
            print(f"metric split={metric.dataset_split} epoch={metric.epoch_number} name={metric.metric_name} value={metric.metric_value:.3f}", flush=True)


if __name__ == "__main__":
    main()
