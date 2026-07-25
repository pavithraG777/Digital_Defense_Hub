from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.pre_encryption_schemas import (
    PreEncryptionFeatures,
    PreEncryptionRequest,
)
from app.pre_encryption_scoring import (
    assess_pre_encryption_risk,
)


client = TestClient(app)
settings = get_settings()


def _base_features() -> dict[str, object]:
    return {
        "window_duration_seconds": 60.0,
        "total_event_count": 1,
        "unique_file_count": 1,
        "unique_extension_count": 1,
        "unique_process_count": 1,
        "created_event_count": 1,
        "modified_event_count": 0,
        "renamed_event_count": 0,
        "extension_changed_event_count": 0,
        "deleted_event_count": 0,
        "hash_changed_event_count": 0,
        "permission_changed_event_count": 0,
        "encrypted_event_count": 0,
        "multiple_file_change_event_count": 0,
        "suspicious_event_count": 0,
        "canary_event_count": 0,
        "honeytoken_event_count": 0,
        "protected_file_event_count": 0,
        "high_entropy_write_count": 0,
        "total_bytes_changed": 1024,
        "event_rate_per_minute": 1.0,
        "file_change_rate_per_minute": 1.0,
        "modification_ratio": 0.0,
        "rename_ratio": 0.0,
        "extension_change_ratio": 0.0,
        "deletion_ratio": 0.0,
        "hash_change_ratio": 0.0,
        "suspicious_event_ratio": 0.0,
        "average_entropy_before": None,
        "average_entropy_after": None,
        "average_entropy_delta": None,
        "maximum_existing_threat_score": 0,
        "ransomware_extension_count": 0,
        "suspicious_process_count": 0,
        "has_canary_trigger": False,
        "has_honeytoken_access": False,
        "has_protected_file_activity": False,
        "has_rapid_file_changes": False,
        "has_mass_modification": False,
        "has_rapid_rename": False,
        "has_extension_change_burst": False,
        "has_deletion_burst": False,
        "has_hash_change_burst": False,
        "has_permission_change_burst": False,
        "has_high_entropy_writes": False,
        "has_encryption_activity": False,
        "has_ransomware_extension": False,
        "has_suspicious_process": False,
    }


def _critical_features() -> dict[str, object]:
    features = _base_features()

    features.update(
        {
            "window_duration_seconds": 30.0,
            "total_event_count": 40,
            "unique_file_count": 40,
            "unique_extension_count": 5,
            "unique_process_count": 1,
            "created_event_count": 0,
            "modified_event_count": 30,
            "renamed_event_count": 5,
            "extension_changed_event_count": 5,
            "suspicious_event_count": 35,
            "canary_event_count": 1,
            "protected_file_event_count": 39,
            "high_entropy_write_count": 30,
            "total_bytes_changed": 50_000_000,
            "event_rate_per_minute": 80.0,
            "file_change_rate_per_minute": 80.0,
            "modification_ratio": 0.75,
            "rename_ratio": 0.125,
            "extension_change_ratio": 0.125,
            "suspicious_event_ratio": 0.875,
            "average_entropy_before": 4.2,
            "average_entropy_after": 7.7,
            "average_entropy_delta": 3.5,
            "maximum_existing_threat_score": 90,
            "ransomware_extension_count": 5,
            "suspicious_process_count": 1,
            "has_canary_trigger": True,
            "has_protected_file_activity": True,
            "has_rapid_file_changes": True,
            "has_mass_modification": True,
            "has_rapid_rename": False,
            "has_extension_change_burst": True,
            "has_high_entropy_writes": True,
            "has_ransomware_extension": True,
            "has_suspicious_process": True,
        }
    )

    return features


def _request_payload(
    features: dict[str, object],
    rule_score: float,
) -> tuple[dict[str, object], str]:
    request_id = str(uuid4())

    payload: dict[str, object] = {
        "request_id": request_id,
        "request_type": (
            "PRE_ENCRYPTION_RANSOMWARE_ASSESSMENT"
        ),
        "schema_version": "1.0.0",
        "organization_id": str(uuid4()),
        "detection_id": str(uuid4()),
        "window_fingerprint": "a" * 64,
        "rule_score": rule_score,
        "features": features,
        "requested_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    return payload, request_id


def _service_headers(
    request_id: str,
) -> dict[str, str]:
    return {
        "X-DDH-Service-Token": (
            settings.service_token.get_secret_value()
        ),
        "X-Request-ID": request_id,
    }


def test_benign_pre_encryption_assessment() -> None:
    payload, _ = _request_payload(
        _base_features(),
        rule_score=5.0,
    )

    request = PreEncryptionRequest.model_validate(
        payload
    )

    assessment = assess_pre_encryption_risk(
        request
    )

    assert assessment.risk_level == "LOW"
    assert assessment.classification == "BENIGN"
    assert (
        assessment.detection_stage
        == "PRE_ENCRYPTION"
    )
    assert not assessment.requires_endpoint_isolation


def test_critical_pre_encryption_assessment() -> None:
    payload, _ = _request_payload(
        _critical_features(),
        rule_score=88.0,
    )

    request = PreEncryptionRequest.model_validate(
        payload
    )

    assessment = assess_pre_encryption_risk(
        request
    )

    assert assessment.combined_risk_score >= 90
    assert assessment.risk_level == "CRITICAL"
    assert assessment.classification == "RANSOMWARE"
    assert (
        assessment.detection_stage
        == "ENCRYPTION_SUSPECTED"
    )
    assert assessment.requires_human_review
    assert assessment.requires_endpoint_isolation


def test_pre_encryption_endpoint_success() -> None:
    payload, request_id = _request_payload(
        _critical_features(),
        rule_score=88.0,
    )

    response = client.post(
        "/v1/ransomware/pre-encryption",
        json=payload,
        headers=_service_headers(
            request_id
        ),
    )

    assert response.status_code == 200

    response_body = response.json()

    assert response_body["success"] is True
    assert (
        response_body["request_id"]
        == request_id
    )

    assessment = response_body["assessment"]

    assert assessment["risk_level"] == "CRITICAL"
    assert (
        assessment["classification"]
        == "RANSOMWARE"
    )


def test_pre_encryption_request_id_mismatch() -> None:
    payload, request_id = _request_payload(
        _base_features(),
        rule_score=5.0,
    )

    headers = _service_headers(
        request_id
    )

    headers["X-Request-ID"] = str(
        uuid4()
    )

    response = client.post(
        "/v1/ransomware/pre-encryption",
        json=payload,
        headers=headers,
    )

    assert response.status_code == 200

    response_body = response.json()

    assert response_body["success"] is False
    assert (
        response_body["error_code"]
        == "REQUEST_ID_MISMATCH"
    )


def test_invalid_pre_encryption_ratio_rejected() -> None:
    features = _base_features()
    features["modification_ratio"] = 1.5

    payload, request_id = _request_payload(
        features,
        rule_score=5.0,
    )

    response = client.post(
        "/v1/ransomware/pre-encryption",
        json=payload,
        headers=_service_headers(
            request_id
        ),
    )

    assert response.status_code == 422