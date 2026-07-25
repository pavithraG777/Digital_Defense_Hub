from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


RiskLevel = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

Classification = Literal[
    "BENIGN",
    "SUSPICIOUS",
    "LIKELY_RANSOMWARE",
    "RANSOMWARE",
]

DetectionStage = Literal[
    "PRE_ENCRYPTION",
    "ENCRYPTION_SUSPECTED",
    "ENCRYPTION_CONFIRMED",
]


class StrictSchema(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )


class PreEncryptionFeatures(StrictSchema):
    window_duration_seconds: float = Field(
        ge=0,
    )

    total_event_count: int = Field(ge=1)
    unique_file_count: int = Field(ge=0)
    unique_extension_count: int = Field(ge=0)
    unique_process_count: int = Field(ge=0)

    created_event_count: int = Field(ge=0)
    modified_event_count: int = Field(ge=0)
    renamed_event_count: int = Field(ge=0)
    extension_changed_event_count: int = Field(ge=0)
    deleted_event_count: int = Field(ge=0)
    hash_changed_event_count: int = Field(ge=0)
    permission_changed_event_count: int = Field(ge=0)
    encrypted_event_count: int = Field(ge=0)

    multiple_file_change_event_count: int = Field(ge=0)
    suspicious_event_count: int = Field(ge=0)

    canary_event_count: int = Field(ge=0)
    honeytoken_event_count: int = Field(ge=0)
    protected_file_event_count: int = Field(ge=0)

    high_entropy_write_count: int = Field(ge=0)
    total_bytes_changed: int = Field(ge=0)

    event_rate_per_minute: float = Field(ge=0)
    file_change_rate_per_minute: float = Field(ge=0)

    modification_ratio: float = Field(ge=0, le=1)
    rename_ratio: float = Field(ge=0, le=1)
    extension_change_ratio: float = Field(ge=0, le=1)
    deletion_ratio: float = Field(ge=0, le=1)
    hash_change_ratio: float = Field(ge=0, le=1)
    suspicious_event_ratio: float = Field(ge=0, le=1)

    average_entropy_before: float | None = Field(
        default=None,
        ge=0,
        le=8,
    )

    average_entropy_after: float | None = Field(
        default=None,
        ge=0,
        le=8,
    )

    average_entropy_delta: float | None = Field(
        default=None,
        ge=-8,
        le=8,
    )

    maximum_existing_threat_score: int = Field(
        ge=0,
        le=100,
    )

    ransomware_extension_count: int = Field(ge=0)
    suspicious_process_count: int = Field(ge=0)

    has_canary_trigger: bool
    has_honeytoken_access: bool
    has_protected_file_activity: bool

    has_rapid_file_changes: bool
    has_mass_modification: bool
    has_rapid_rename: bool
    has_extension_change_burst: bool
    has_deletion_burst: bool
    has_hash_change_burst: bool
    has_permission_change_burst: bool

    has_high_entropy_writes: bool
    has_encryption_activity: bool
    has_ransomware_extension: bool
    has_suspicious_process: bool

    @model_validator(mode="after")
    def validate_event_counts(
        self,
    ) -> "PreEncryptionFeatures":
        event_bounded_counts = {
            "unique_file_count": self.unique_file_count,
            "unique_extension_count": (
                self.unique_extension_count
            ),
            "unique_process_count": (
                self.unique_process_count
            ),
            "suspicious_event_count": (
                self.suspicious_event_count
            ),
            "canary_event_count": self.canary_event_count,
            "honeytoken_event_count": (
                self.honeytoken_event_count
            ),
            "protected_file_event_count": (
                self.protected_file_event_count
            ),
            "high_entropy_write_count": (
                self.high_entropy_write_count
            ),
            "ransomware_extension_count": (
                self.ransomware_extension_count
            ),
            "suspicious_process_count": (
                self.suspicious_process_count
            ),
        }

        for name, value in event_bounded_counts.items():
            if value > self.total_event_count:
                raise ValueError(
                    f"{name} cannot exceed "
                    "total_event_count"
                )

        return self


class PreEncryptionRiskFactor(StrictSchema):
    code: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)

    weight: float = Field(ge=0, le=1)
    score: float = Field(ge=0, le=100)
    contribution: float = Field(ge=0, le=100)

    signal_count: int = Field(default=0, ge=0)


class PreEncryptionRecommendedAction(StrictSchema):
    code: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=1000)

    priority: RiskLevel

    automatic: bool = False


class PreEncryptionRequest(StrictSchema):
    request_id: UUID

    request_type: Literal[
        "PRE_ENCRYPTION_RANSOMWARE_ASSESSMENT"
    ]

    schema_version: Literal["1.0.0"]

    organization_id: UUID
    detection_id: UUID

    window_fingerprint: str = Field(
        min_length=32,
        max_length=128,
    )

    rule_score: float = Field(ge=0, le=100)

    features: PreEncryptionFeatures

    requested_at: datetime


class PreEncryptionAssessment(StrictSchema):
    ai_score: float = Field(ge=0, le=100)
    combined_risk_score: float = Field(ge=0, le=100)

    threat_probability: float = Field(ge=0, le=100)
    confidence_score: float = Field(ge=0, le=100)

    risk_level: RiskLevel
    classification: Classification
    detection_stage: DetectionStage

    risk_factors: list[PreEncryptionRiskFactor]

    recommended_actions: list[
        PreEncryptionRecommendedAction
    ]

    score_explanation: str = Field(
        min_length=1,
        max_length=5000,
    )

    requires_human_review: bool
    requires_endpoint_isolation: bool

    model_name: str = Field(min_length=1, max_length=150)
    model_version: str = Field(min_length=1, max_length=50)
    policy_version: str = Field(min_length=1, max_length=50)


class PreEncryptionResponse(StrictSchema):
    request_id: UUID
    success: bool

    assessment: PreEncryptionAssessment | None = None

    error_code: str | None = None
    error_message: str | None = None

    processed_at: datetime