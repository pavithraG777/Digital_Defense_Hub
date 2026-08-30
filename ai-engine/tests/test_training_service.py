import json
import os
import tempfile
from pathlib import Path

import torch
import numpy as np

os.environ.setdefault("AI_RISK_SERVICE_TOKEN", "12345678901234567890123456789012")

from app.image_training_service import binary_classification_metrics, validate_image_dataset
from app.media_model_runner import MediaModelRunner
from app.training_schemas import ImageTrainingRequest


def test_validate_image_dataset_accepts_deepfake_class_name() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        dataset_root = root / "datasets"
        dataset_dir = dataset_root / "sample"
        (dataset_dir / "authentic").mkdir(parents=True)
        (dataset_dir / "deepfake").mkdir(parents=True)
        (dataset_dir / "authentic" / "a.jpg").write_bytes(b"fake-image")
        (dataset_dir / "deepfake" / "b.jpg").write_bytes(b"fake-image")
        (dataset_dir / "dataset.json").write_text(
            json.dumps(
                {
                    "type": "image_classification",
                    "classes": ["authentic", "deepfake"],
                    "image_size": 64,
                }
            ),
            encoding="utf-8",
        )

        candidate, manifest = validate_image_dataset(str(dataset_dir), dataset_root)

        assert candidate == dataset_dir.resolve()
        assert manifest["classes"] == ["authentic", "deepfake"]


def test_model_runner_loads_ddh_training_checkpoint() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        checkpoint_path = Path(temp_dir) / "trained-model.pth"
        model = torch.nn.Sequential(
            torch.nn.Conv2d(3, 16, kernel_size=3, padding=1),
            torch.nn.ReLU(),
            torch.nn.MaxPool2d(2),
            torch.nn.Conv2d(16, 32, kernel_size=3, padding=1),
            torch.nn.ReLU(),
            torch.nn.AdaptiveAvgPool2d((1, 1)),
            torch.nn.Flatten(),
            torch.nn.Linear(32, 2),
        )
        torch.save(
            {
                "format_version": "1.0",
                "architecture": "ddh_cnn_v1",
                "classes": ["authentic", "deepfake"],
                "image_size": 64,
                "state_dict": model.state_dict(),
            },
            checkpoint_path,
        )

        runner = MediaModelRunner.__new__(MediaModelRunner)
        loaded_model = runner._load_pytorch_model(checkpoint_path)

        output = loaded_model(torch.zeros((1, 3, 64, 64)))
        assert tuple(output.shape) == (1, 2)


def test_training_request_defaults_test_split_to_zero() -> None:
    request = ImageTrainingRequest(
        request_id="11111111-1111-4111-8111-111111111111",
        training_job_id="22222222-2222-4222-8222-222222222222",
        organization_id="33333333-3333-4333-8333-333333333333",
        dataset_version_id="44444444-4444-4444-8444-444444444444",
        dataset_path="/datasets/sample",
        model_code="test-model",
    )
    assert request.test_percent == 0
    assert request.deepfake_class_weight == 1.0
    assert request.selection_metric == "accuracy"


def test_training_request_accepts_forensic_selection_controls() -> None:
    request = ImageTrainingRequest(
        request_id="11111111-1111-4111-8111-111111111111",
        training_job_id="22222222-2222-4222-8222-222222222222",
        organization_id="33333333-3333-4333-8333-333333333333",
        dataset_version_id="44444444-4444-4444-8444-444444444444",
        dataset_path="/datasets/sample",
        model_code="test-model",
        deepfake_class_weight=1.25,
        selection_metric="f1",
    )
    assert request.deepfake_class_weight == 1.25
    assert request.selection_metric == "f1"


def test_training_request_accepts_synthetic_detector_scope() -> None:
    request = ImageTrainingRequest(
        request_id="11111111-1111-4111-8111-111111111111",
        training_job_id="22222222-2222-4222-8222-222222222222",
        organization_id="33333333-3333-4333-8333-333333333333",
        dataset_version_id="44444444-4444-4444-8444-444444444444",
        dataset_path="/datasets/synthetic",
        model_code="synthetic-image-detector",
        detector_scope="AI_GENERATED_IMAGE_DETECTION",
    )
    assert request.detector_scope == "AI_GENERATED_IMAGE_DETECTION"


def test_binary_classification_metrics_include_forensic_quality_measures() -> None:
    metrics = binary_classification_metrics([0, 0, 1, 1], [0, 1, 1, 1])
    assert metrics["accuracy"] == 75.0
    assert round(metrics["precision"], 2) == 66.67
    assert metrics["recall"] == 100.0
    assert round(metrics["f1"], 2) == 80.0
    assert metrics["confusion_fp"] == 1.0


def test_model_runner_loads_mobilenet_forensics_checkpoint() -> None:
    from torchvision.models import mobilenet_v3_small
    with tempfile.TemporaryDirectory() as temp_dir:
        checkpoint_path = Path(temp_dir) / "mobilenet.pth"
        model = mobilenet_v3_small(weights=None)
        model.classifier[-1] = torch.nn.Linear(model.classifier[-1].in_features, 2)
        torch.save({"format_version": "1.0", "architecture": "mobilenet_v3_small_forensics_v1",
                    "classes": ["authentic", "deepfake"], "image_size": 64,
                    "state_dict": model.state_dict()}, checkpoint_path)
        runner = MediaModelRunner.__new__(MediaModelRunner)
        loaded = runner._load_pytorch_model(checkpoint_path)
        assert tuple(loaded(torch.zeros((1, 3, 64, 64))).shape) == (1, 2)


def test_face_context_preprocessing_uses_square_center_fallback() -> None:
    image = np.zeros((100, 200, 3), dtype=np.uint8)
    prepared = MediaModelRunner._prepare_image_region(
        image,
        {
            "preprocessing": "EARLY_WINDOW_FACE_CONTEXT_CROP_V2",
            "context_scale": 2.35,
        },
    )
    assert prepared.shape == (100, 100, 3)


def test_standard_preprocessing_keeps_the_full_image() -> None:
    image = np.zeros((100, 200, 3), dtype=np.uint8)
    prepared = MediaModelRunner._prepare_image_region(image, {})
    assert prepared is image
