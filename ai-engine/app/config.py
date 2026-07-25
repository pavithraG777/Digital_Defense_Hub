from functools import lru_cache

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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()