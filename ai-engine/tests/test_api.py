from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from tests.test_scoring import build_features


client = TestClient(app)


def authentication_headers(
    request_id: str | None = None,
) -> dict[str, str]:
    settings = get_settings()

    headers = {
        "X-DDH-Service-Token": (
            settings.service_token
            .get_secret_value()
        ),
    }

    if request_id is not None:
        headers["X-Request-ID"] = request_id

    return headers


def build_risk_request() -> dict[str, object]:
    request_id = str(uuid4())

    features = build_features(
        incident_category="CANARY_FILE_TRIGGER",
        incident_severity="CRITICAL",
        incident_priority="URGENT",
        detection_source="CANARY_FILE",
        linked_threat_count=1,
        critical_threat_count=1,
        malicious_threat_count=1,
        unresolved_threat_count=1,
        maximum_threat_score=100,
        average_threat_score=100,
        maximum_confidence_score=98,
        file_event_count=1,
        suspicious_file_event_count=1,
        hash_change_event_count=1,
        canary_file_event_count=1,
        has_canary_trigger=True,
        has_hash_changes=True,
    )

    return {
        "request_id": request_id,
        "request_type": (
            "INCIDENT_RANSOMWARE_RISK"
        ),
        "schema_version": "1.0.0",
        "organization_id": str(uuid4()),
        "incident_id": str(uuid4()),
        "features": features.model_dump(
            mode="json"
        ),
        "requested_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }


def test_health_requires_authentication() -> None:
    response = client.get("/health")

    assert response.status_code == 401


def test_health_with_valid_token() -> None:
    response = client.get(
        "/health",
        headers=authentication_headers(),
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "healthy"
    assert body["model_name"] == (
        "DDH_INCIDENT_RANSOMWARE_RISK"
    )


def test_incident_risk_endpoint() -> None:
    request_body = build_risk_request()

    request_id = str(
        request_body["request_id"]
    )

    response = client.post(
        "/v1/risk/incident",
        json=request_body,
        headers=authentication_headers(
            request_id
        ),
    )

    assert response.status_code == 200

    body = response.json()

    assert body["request_id"] == request_id
    assert body["success"] is True
    assert body["assessment"]["risk_level"] == (
        "CRITICAL"
    )
    assert (
        body["assessment"][
            "overall_risk_score"
        ]
        >= 78
    )
    assert (
        body["assessment"][
            "threat_probability"
        ]
        >= 90
    )


def test_request_id_mismatch() -> None:
    request_body = build_risk_request()

    response = client.post(
        "/v1/risk/incident",
        json=request_body,
        headers=authentication_headers(
            str(uuid4())
        ),
    )

    assert response.status_code == 200

    body = response.json()

    assert body["success"] is False
    assert body["error_code"] == (
        "REQUEST_ID_MISMATCH"
    )


def test_invalid_service_token() -> None:
    request_body = build_risk_request()

    response = client.post(
        "/v1/risk/incident",
        json=request_body,
        headers={
            "X-DDH-Service-Token": (
                "invalid-service-token"
            ),
            "X-Request-ID": str(
                request_body["request_id"]
            ),
        },
    )

    assert response.status_code == 401


def test_image_training_rejects_dataset_outside_mount() -> None:
    request_id = str(uuid4())
    response = client.post(
        "/v1/model-training/image-classification",
        json={
            "request_id": request_id,
            "training_job_id": str(uuid4()),
            "organization_id": str(uuid4()),
            "dataset_version_id": str(uuid4()),
            "dataset_path": "/outside/dataset",
            "model_code": "DFI001",
        },
        headers=authentication_headers(request_id),
    )

    assert response.status_code == 200
    assert response.json()["success"] is False
    assert response.json()["error_code"] == "INVALID_TRAINING_DATASET"
