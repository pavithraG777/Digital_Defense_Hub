from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


MediaType = Literal[
    "IMAGE",
    "VIDEO",
    "AUDIO",
    "DOCUMENT",
]

AnalysisJobType = Literal[
    "DEEPFAKE_IMAGE_DETECTION",
    "AI_GENERATED_IMAGE_DETECTION",
    "DEEPFAKE_VIDEO_DETECTION",
    "DEEPFAKE_AUDIO_DETECTION",
    "IMAGE_FORENSICS",
    "VIDEO_FORENSICS",
    "AUDIO_FORENSICS",
    "OCR_EXTRACTION",
]

ExecutionDevice = Literal[
    "AUTO",
    "CPU",
    "CUDA",
]

ModelFormat = Literal[
    "PTH",
    "PT",
    "ONNX",
    "CUSTOM",
]

EngineRuntime = Literal[
    "PYTORCH",
    "ONNX_RUNTIME",
    "OPENCV",
    "TESSERACT",
    "HYBRID",
    "HEURISTIC_FALLBACK",
]

DeepfakeResult = Literal[
    "AUTHENTIC",
    "LIKELY_AUTHENTIC",
    "SUSPICIOUS",
    "LIKELY_DEEPFAKE",
    "DEEPFAKE",
    "INCONCLUSIVE",
    "ERROR",
]

ForensicResult = Literal[
    "AUTHENTIC",
    "SUSPICIOUS",
    "MANIPULATED",
    "CORRUPTED",
    "INCONCLUSIVE",
    "ERROR",
]

OCRExtractionResult = Literal[
    "TEXT_FOUND",
    "NO_TEXT",
    "PARTIAL",
    "INCONCLUSIVE",
    "ERROR",
]


class StrictSchema(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )


class ModelExecutionSpecification(StrictSchema):
    model_name: str = Field(
        min_length=1,
        max_length=150,
    )
    model_version: str = Field(
        min_length=1,
        max_length=50,
    )
    model_format: ModelFormat

    model_file_path: str = Field(
        min_length=1,
        max_length=2000,
    )
    model_file_hash: str = Field(
        min_length=64,
        max_length=128,
        pattern=r"^[0-9A-Fa-f]+$",
    )

    confidence_threshold: float = Field(
        default=50,
        ge=0,
        le=100,
    )

    configuration: dict[str, Any] = Field(
        default_factory=dict,
    )


class MediaAnalysisRequest(StrictSchema):
    request_id: UUID

    request_type: Literal[
        "MULTIMODAL_MEDIA_ANALYSIS"
    ]
    schema_version: Literal["1.0.0"]

    organization_id: UUID
    analysis_job_id: UUID

    media_asset_id: UUID | None = None
    evidence_id: UUID | None = None
    evidence_file_id: UUID | None = None

    job_type: AnalysisJobType
    media_type: MediaType

    file_name: str = Field(
        min_length=1,
        max_length=255,
    )
    mime_type: str = Field(
        min_length=1,
        max_length=150,
    )
    source_file_path: str = Field(
        min_length=1,
        max_length=4000,
    )

    file_size_bytes: int = Field(
        ge=0,
    )
    file_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9A-Fa-f]{64}$",
    )

    execution_device: ExecutionDevice = "CPU"

    model: ModelExecutionSpecification | None = None

    parameters: dict[str, Any] = Field(
        default_factory=dict,
    )

    requested_at: datetime

    @model_validator(mode="after")
    def validate_analysis_source(
        self,
    ) -> "MediaAnalysisRequest":
        if (
            self.media_asset_id is None
            and self.evidence_id is None
        ):
            raise ValueError(
                "media_asset_id or evidence_id is required"
            )

        allowed_job_types: dict[
            str,
            set[str],
        ] = {
            "IMAGE": {
                "DEEPFAKE_IMAGE_DETECTION",
                "AI_GENERATED_IMAGE_DETECTION",
                "IMAGE_FORENSICS",
                "OCR_EXTRACTION",
            },
            "VIDEO": {
                "DEEPFAKE_VIDEO_DETECTION",
                "VIDEO_FORENSICS",
                "OCR_EXTRACTION",
            },
            "AUDIO": {
                "DEEPFAKE_AUDIO_DETECTION",
                "AUDIO_FORENSICS",
            },
            "DOCUMENT": {
                "OCR_EXTRACTION",
            },
        }

        if self.job_type not in allowed_job_types[
            self.media_type
        ]:
            raise ValueError(
                f"{self.job_type} is not supported "
                f"for {self.media_type}"
            )

        return self


class AnalysisSignal(StrictSchema):
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

    score: float = Field(
        ge=0,
        le=100,
    )
    confidence: float = Field(
        ge=0,
        le=100,
    )

    detected: bool


class SuspiciousRegion(StrictSchema):
    region_type: str = Field(
        min_length=1,
        max_length=100,
    )

    frame_number: int | None = Field(
        default=None,
        ge=0,
    )
    page_number: int | None = Field(
        default=None,
        ge=1,
    )
    timestamp_seconds: float | None = Field(
        default=None,
        ge=0,
    )

    bounding_box: tuple[
        float,
        float,
        float,
        float,
    ] | None = None

    score: float = Field(
        ge=0,
        le=100,
    )
    description: str = Field(
        default="",
        max_length=1000,
    )


class DeepfakeAssessment(StrictSchema):
    media_type: Literal[
        "IMAGE",
        "VIDEO",
        "AUDIO",
    ]

    detection_result: DeepfakeResult

    deepfake_probability: float = Field(
        ge=0,
        le=100,
    )
    authenticity_probability: float = Field(
        ge=0,
        le=100,
    )
    confidence_score: float = Field(
        ge=0,
        le=100,
    )

    faces_detected: int | None = Field(
        default=None,
        ge=0,
    )
    manipulated_faces_detected: int | None = Field(
        default=None,
        ge=0,
    )

    total_frames_analyzed: int | None = Field(
        default=None,
        ge=0,
    )
    suspicious_frames: int | None = Field(
        default=None,
        ge=0,
    )

    audio_duration_seconds: float | None = Field(
        default=None,
        ge=0,
    )

    lip_sync_anomaly_detected: bool = False
    facial_artifact_detected: bool = False
    audio_manipulation_detected: bool = False
    metadata_inconsistency_detected: bool = False

    detection_summary: str = Field(
        min_length=1,
        max_length=5000,
    )

    signals: list[AnalysisSignal] = Field(
        default_factory=list,
    )
    feature_data: dict[str, Any] = Field(
        default_factory=dict,
    )
    suspicious_regions: list[
        SuspiciousRegion
    ] = Field(
        default_factory=list,
    )

    visualization_file_path: str | None = None


class MediaForensicsAssessment(StrictSchema):
    media_type: Literal[
        "IMAGE",
        "VIDEO",
        "AUDIO",
    ]

    forensic_result: ForensicResult

    confidence_score: float = Field(
        ge=0,
        le=100,
    )

    editing_trace_detected: bool = False
    compression_anomaly_detected: bool = False
    copy_move_detected: bool = False
    splicing_detected: bool = False

    frame_duplication_detected: bool = False
    frame_deletion_detected: bool = False

    audio_discontinuity_detected: bool = False
    noise_inconsistency_detected: bool = False
    timestamp_anomaly_detected: bool = False

    analysis_summary: str = Field(
        min_length=1,
        max_length=5000,
    )
    findings: list[str] = Field(
        default_factory=list,
    )

    signals: list[AnalysisSignal] = Field(
        default_factory=list,
    )
    suspicious_locations: list[
        SuspiciousRegion
    ] = Field(
        default_factory=list,
    )
    forensic_feature_data: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict,
    )

    visualization_file_path: str | None = None


class OCRAssessment(StrictSchema):
    source_media_type: Literal[
        "IMAGE",
        "VIDEO",
        "DOCUMENT",
    ]

    extraction_result: OCRExtractionResult

    ocr_engine: str = Field(
        min_length=1,
        max_length=150,
    )
    engine_version: str | None = Field(
        default=None,
        max_length=50,
    )
    detected_language: str | None = Field(
        default=None,
        max_length=50,
    )

    total_pages: int | None = Field(
        default=None,
        ge=0,
    )
    total_frames: int | None = Field(
        default=None,
        ge=0,
    )

    extracted_text: str | None = None

    confidence_score: float | None = Field(
        default=None,
        ge=0,
        le=100,
    )

    word_count: int = Field(
        default=0,
        ge=0,
    )
    character_count: int = Field(
        default=0,
        ge=0,
    )

    page_results: list[
        dict[str, Any]
    ] = Field(
        default_factory=list,
    )
    bounding_box_data: list[
        dict[str, Any]
    ] = Field(
        default_factory=list,
    )
    preprocessing_data: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict,
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )

    requires_manual_correction: bool = False
    output_file_path: str | None = None


class MediaAnalysisResponse(StrictSchema):
    request_id: UUID
    analysis_job_id: UUID
    organization_id: UUID

    success: bool

    runtime: EngineRuntime | None = None

    deepfake_assessment: (
        DeepfakeAssessment | None
    ) = None
    forensics_assessment: (
        MediaForensicsAssessment | None
    ) = None
    ocr_assessment: OCRAssessment | None = None

    processing_duration_ms: int = Field(
        default=0,
        ge=0,
    )

    warnings: list[str] = Field(
        default_factory=list,
    )

    error_code: str | None = None
    error_message: str | None = None

    processed_at: datetime

    @model_validator(mode="after")
    def validate_response_payload(
        self,
    ) -> "MediaAnalysisResponse":
        assessments = [
            self.deepfake_assessment,
            self.forensics_assessment,
            self.ocr_assessment,
        ]

        assessment_count = sum(
            value is not None
            for value in assessments
        )

        if self.success and assessment_count != 1:
            raise ValueError(
                "successful response must contain "
                "exactly one assessment"
            )

        if not self.success:
            if not self.error_code:
                raise ValueError(
                    "failed response requires error_code"
                )

            if not self.error_message:
                raise ValueError(
                    "failed response requires error_message"
                )

        return self
