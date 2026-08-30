from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.schemas import StrictSchema


class ImageTrainingRequest(StrictSchema):
    request_id: UUID
    training_job_id: UUID
    organization_id: UUID
    dataset_version_id: UUID
    dataset_path: str = Field(min_length=1, max_length=4000)
    model_code: str = Field(min_length=1, max_length=100)
    detector_scope: Literal[
        "DEEPFAKE_IMAGE_DETECTION",
        "AI_GENERATED_IMAGE_DETECTION",
    ] = "DEEPFAKE_IMAGE_DETECTION"
    epochs: int = Field(default=5, ge=1, le=100)
    batch_size: int = Field(default=16, ge=1, le=128)
    learning_rate: float = Field(default=0.001, gt=0, le=1)
    deepfake_class_weight: float = Field(default=1.0, ge=1.0, le=3.0)
    selection_metric: Literal["accuracy", "f1", "recall"] = "accuracy"
    validation_percent: int = Field(default=20, ge=10, le=40)
    test_percent: int = Field(default=0, ge=0, le=40)
    seed: int = Field(default=42, ge=0, le=2_147_483_647)

    @field_validator("dataset_path")
    @classmethod
    def normalize_dataset_path(cls, value: str) -> str:
        return value.strip()


class TrainingMetric(StrictSchema):
    metric_name: str
    metric_value: float
    dataset_split: Literal["TRAIN", "VALIDATION", "TEST"]
    epoch_number: int = Field(ge=1)


class ImageTrainingResponse(StrictSchema):
    request_id: UUID
    training_job_id: UUID
    organization_id: UUID
    success: bool
    artifact_path: str | None = None
    artifact_sha256: str | None = None
    artifact_format: str | None = None
    training_record_count: int | None = None
    validation_record_count: int | None = None
    test_record_count: int | None = None
    metrics: list[TrainingMetric] = Field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    processed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
