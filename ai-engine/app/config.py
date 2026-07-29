from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    app_name: str = Field(
        default="Digital Defense Hub AI Risk Engine",
        validation_alias="AI_RISK_APP_NAME",
    )
    app_version: str = Field(
        default="1.0.0",
        validation_alias="AI_RISK_APP_VERSION",
    )
    environment: str = Field(
        default="development",
        validation_alias="AI_RISK_ENVIRONMENT",
    )

    host: str = Field(
        default="127.0.0.1",
        validation_alias="AI_RISK_HOST",
    )
    port: int = Field(
        default=8091,
        ge=1,
        le=65535,
        validation_alias="AI_RISK_PORT",
    )

    service_token: SecretStr = Field(
        validation_alias="AI_RISK_SERVICE_TOKEN",
    )

    model_name: str = Field(
        default="DDH_INCIDENT_RANSOMWARE_RISK",
        validation_alias="AI_RISK_MODEL_NAME",
    )
    model_version: str = Field(
        default="1.0.0",
        validation_alias="AI_RISK_MODEL_VERSION",
    )
    policy_version: str = Field(
        default="2026.07",
        validation_alias="AI_RISK_POLICY_VERSION",
    )

    maximum_request_bytes: int = Field(
        default=1_048_576,
        ge=1024,
        le=10_485_760,
        validation_alias="AI_RISK_MAXIMUM_REQUEST_BYTES",
    )

    media_model_root: Path = Field(
        default=Path("models"),
        validation_alias="MEDIA_FORENSICS_MODEL_ROOT",
    )
    media_workspace_root: Path = Field(
        default=Path("storage/media-analysis"),
        validation_alias="MEDIA_FORENSICS_WORKSPACE_ROOT",
    )
    media_backend_storage_root: Path = Field(
        default=Path(
            "../backend-go/storage/media-analysis"
        ),
        validation_alias=(
            "MEDIA_FORENSICS_BACKEND_STORAGE_ROOT"
        ),
    )

    media_backend_storage_root: Path = Field(
        default=Path(
            "../backend-go/storage/media-analysis"
        ),
        validation_alias=(
            "MEDIA_FORENSICS_BACKEND_STORAGE_ROOT"
        ),
    )

    tesseract_executable: str = Field(
        default="tesseract",
        validation_alias="MEDIA_FORENSICS_TESSERACT_EXECUTABLE",
    )
    ffmpeg_executable: str = Field(
        default="ffmpeg",
        validation_alias="MEDIA_FORENSICS_FFMPEG_EXECUTABLE",
    )

    media_maximum_file_bytes: int = Field(
        default=536_870_912,
        ge=1_048_576,
        le=2_147_483_648,
        validation_alias="MEDIA_FORENSICS_MAXIMUM_FILE_BYTES",
    )
    media_analysis_timeout_seconds: int = Field(
        default=300,
        ge=30,
        le=1800,
        validation_alias="MEDIA_FORENSICS_ANALYSIS_TIMEOUT_SECONDS",
    )

    media_maximum_video_frames: int = Field(
        default=120,
        ge=1,
        le=5000,
        validation_alias="MEDIA_FORENSICS_MAXIMUM_VIDEO_FRAMES",
    )
    media_video_frame_interval_seconds: float = Field(
        default=1.0,
        ge=0.1,
        le=60.0,
        validation_alias="MEDIA_FORENSICS_VIDEO_FRAME_INTERVAL_SECONDS",
    )
    media_maximum_audio_seconds: int = Field(
        default=600,
        ge=1,
        le=7200,
        validation_alias="MEDIA_FORENSICS_MAXIMUM_AUDIO_SECONDS",
    )
    media_maximum_document_pages: int = Field(
        default=100,
        ge=1,
        le=2000,
        validation_alias="MEDIA_FORENSICS_MAXIMUM_DOCUMENT_PAGES",
    )

    media_ocr_languages: str = Field(
        default="eng",
        validation_alias="MEDIA_FORENSICS_OCR_LANGUAGES",
    )
    media_torch_device: str = Field(
        default="cpu",
        validation_alias="MEDIA_FORENSICS_TORCH_DEVICE",
    )
    media_allow_heuristic_fallback: bool = Field(
        default=True,
        validation_alias="MEDIA_FORENSICS_ALLOW_HEURISTIC_FALLBACK",
    )

    training_dataset_root: Path = Field(
        default=Path("/datasets"),
        validation_alias="ML_TRAINING_DATASET_ROOT",
    )
    training_artifact_root: Path = Field(
        default=Path("models/trained"),
        validation_alias="ML_TRAINING_ARTIFACT_ROOT",
    )
    training_maximum_epochs: int = Field(
        default=20,
        ge=1,
        le=100,
        validation_alias="ML_TRAINING_MAXIMUM_EPOCHS",
    )
    training_maximum_samples: int = Field(
        default=100_000,
        ge=4,
        le=1_000_000,
        validation_alias="ML_TRAINING_MAXIMUM_SAMPLES",
    )

    @field_validator("service_token")
    @classmethod
    def validate_service_token(
        cls,
        value: SecretStr,
    ) -> SecretStr:
        normalized_token = value.get_secret_value().strip()

        if len(normalized_token) < 32:
            raise ValueError(
                "AI_RISK_SERVICE_TOKEN must contain at least 32 characters"
            )

        return SecretStr(normalized_token)

    @field_validator(
        "tesseract_executable",
        "ffmpeg_executable",
        "media_ocr_languages",
    )
    @classmethod
    def validate_required_text(
        cls,
        value: str,
    ) -> str:
        normalized_value = value.strip()

        if not normalized_value:
            raise ValueError(
                "media forensics executable and language values cannot be empty"
            )

        return normalized_value

    @field_validator("media_torch_device")
    @classmethod
    def validate_torch_device(
        cls,
        value: str,
    ) -> str:
        normalized_value = value.strip().lower()

        if normalized_value not in {
            "auto",
            "cpu",
            "cuda",
        }:
            raise ValueError(
                "MEDIA_FORENSICS_TORCH_DEVICE must be auto, cpu or cuda"
            )

        return normalized_value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
