from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


NonNegativeInteger = Annotated[int, Field(ge=0)]
NonNegativeNumber = Annotated[float, Field(ge=0)]
PercentageScore = Annotated[float, Field(ge=0, le=100)]

RiskLevel = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]


class StrictSchema(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


class IncidentRiskFeatures(StrictSchema):
    incident_category: str = Field(
        min_length=1,
        max_length=100,
    )
    incident_severity: str = Field(
        min_length=1,
        max_length=50,
    )
    incident_priority: str = Field(
        min_length=1,
        max_length=50,
    )
    incident_status: str = Field(
        min_length=1,
        max_length=50,
    )
    detection_source: str = Field(
        min_length=1,
        max_length=100,
    )

    data_exposure_suspected: bool
    ransomware_suspected: bool
    device_isolated: bool
    evidence_preserved: bool

    affected_record_count: NonNegativeInteger
    estimated_financial_impact: NonNegativeNumber

    incident_age_minutes: NonNegativeNumber
    reporting_delay_minutes: NonNegativeNumber
    investigation_age_minutes: NonNegativeNumber

    linked_threat_count: NonNegativeInteger
    critical_threat_count: NonNegativeInteger
    high_threat_count: NonNegativeInteger
    malicious_threat_count: NonNegativeInteger
    confirmed_threat_count: NonNegativeInteger
    unresolved_threat_count: NonNegativeInteger

    maximum_threat_score: PercentageScore
    average_threat_score: PercentageScore
    maximum_confidence_score: PercentageScore

    total_threat_occurrences: NonNegativeInteger
    total_affected_file_count: NonNegativeInteger
    total_affected_device_count: NonNegativeInteger

    file_event_count: NonNegativeInteger
    suspicious_file_event_count: NonNegativeInteger
    encrypted_event_count: NonNegativeInteger
    multiple_file_change_event_count: NonNegativeInteger
    hash_change_event_count: NonNegativeInteger
    deleted_file_event_count: NonNegativeInteger
    permission_change_event_count: NonNegativeInteger

    canary_file_event_count: NonNegativeInteger
    honeytoken_event_count: NonNegativeInteger
    protected_file_event_count: NonNegativeInteger

    unique_device_count: NonNegativeInteger
    event_window_seconds: NonNegativeNumber
    event_rate_per_minute: NonNegativeNumber

    evidence_count: NonNegativeInteger
    verified_evidence_count: NonNegativeInteger
    tampered_evidence_count: NonNegativeInteger

    has_canary_trigger: bool
    has_honeytoken_access: bool
    has_encryption_indicators: bool
    has_rapid_file_changes: bool
    has_hash_changes: bool
    has_file_deletion: bool
    has_permission_changes: bool


class RiskEngineRequest(StrictSchema):
    request_id: UUID

    request_type: Literal["INCIDENT_RANSOMWARE_RISK"]
    schema_version: Literal["1.0.0"]

    organization_id: UUID
    incident_id: UUID

    features: IncidentRiskFeatures

    requested_at: datetime

    @field_validator("requested_at")
    @classmethod
    def normalize_requested_at(
        cls,
        value: datetime,
    ) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                "requested_at must contain timezone information"
            )

        return value.astimezone(timezone.utc)


class RiskFactor(StrictSchema):
    code: str = Field(
        min_length=1,
        max_length=100,
    )
    name: str = Field(
        min_length=1,
        max_length=200,
    )
    category: str = Field(
        min_length=1,
        max_length=100,
    )
    description: str = Field(
        default="",
        max_length=1000,
    )

    weight: float = Field(
        ge=0,
        le=1,
    )
    score: PercentageScore
    contribution: PercentageScore


class RiskEngineAssessment(StrictSchema):
    overall_risk_score: PercentageScore
    risk_level: RiskLevel

    threat_probability: PercentageScore
    integrity_risk_score: PercentageScore
    confidentiality_risk_score: PercentageScore
    availability_risk_score: PercentageScore
    confidence_score: PercentageScore

    risk_factors: list[RiskFactor] = Field(
        default_factory=list,
    )

    score_explanation: str = Field(
        min_length=1,
        max_length=5000,
    )
    recommended_action: str = Field(
        min_length=1,
        max_length=5000,
    )

    requires_human_review: bool

    model_name: str = Field(
        min_length=1,
        max_length=200,
    )
    model_version: str = Field(
        min_length=1,
        max_length=100,
    )


class RiskEngineResponse(StrictSchema):
    request_id: UUID
    success: bool

    assessment: RiskEngineAssessment | None = None

    error_code: str | None = Field(
        default=None,
        max_length=100,
    )
    error_message: str | None = Field(
        default=None,
        max_length=2000,
    )

    processed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    @model_validator(mode="after")
    def validate_response_state(
        self,
    ) -> RiskEngineResponse:
        if self.success:
            if self.assessment is None:
                raise ValueError(
                    "successful response requires an assessment"
                )

            if self.error_code is not None:
                raise ValueError(
                    "successful response cannot contain error_code"
                )

            if self.error_message is not None:
                raise ValueError(
                    "successful response cannot contain error_message"
                )

            return self

        if self.assessment is not None:
            raise ValueError(
                "failed response cannot contain an assessment"
            )

        if not self.error_code:
            raise ValueError(
                "failed response requires error_code"
            )

        if not self.error_message:
            raise ValueError(
                "failed response requires error_message"
            )

        return self