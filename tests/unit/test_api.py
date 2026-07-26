from unittest.mock import patch

from fastapi.testclient import TestClient

from sentinel.api import app
from sentinel.api.service import AnalysisResult
from sentinel.classification import (
    AnomalyType,
    ClassificationResult,
)
from sentinel.explainability import SecurityExplanation

client = TestClient(app)


def test_root_endpoint() -> None:
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "SentinelAI"
    assert data["version"] == "0.1.0"


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data == {
        "status": "healthy",
        "service": "SentinelAI",
        "version": "0.1.0",
    }


def test_openapi_schema_is_available() -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    schema = response.json()

    assert schema["info"]["title"] == "SentinelAI"


def test_swagger_docs_are_available() -> None:
    response = client.get("/docs")

    assert response.status_code == 200


def valid_event_payload() -> dict[str, object]:
    return {
        "event_id": "EVENT_API_TEST",
        "entity_id": "USER_00001",
        "entity_type": "user",
        "timestamp": "2026-07-20T10:00:00Z",
        "source_ip": "203.0.113.10",
        "geo_location": {
            "country_code": "IN",
            "city": "Hyderabad",
            "latitude": 17.385,
            "longitude": 78.4867,
        },
        "resource_accessed": "internal-api",
        "auth_method": "mfa",
        "outcome": "success",
        "session_duration_seconds": 300,
        "command_sequence": [
            "GET /profile",
        ],
        "device_fingerprint": {
            "fingerprint_id": (
                "device_api_test_12345678"
            ),
            "operating_system": "macOS",
            "browser": "Firefox",
            "device_type": "laptop",
        },
    }


def test_analyze_endpoint_returns_assessment() -> None:
    explanation = SecurityExplanation(
        event_id="EVENT_API_TEST",
        entity_id="USER_00001",
        risk_score=55.0,
        severity="medium",
        summary="Behavioral deviations warrant review.",
        reasons=(
            "Travel would require impossible speed",
        ),
        ml_anomaly_score=-0.05,
        ml_flagged=False,
        ml_contribution=0.0,
        behavioral_contribution=55.0,
    )

    result = AnalysisResult(
        explanation=explanation,
        classification=ClassificationResult(
            anomaly_type=AnomalyType.IMPOSSIBLE_TRAVEL,
            confidence=0.95,
            evidence=(
                "Travel would require impossible speed",
            ),
        ),
    )

    with patch(
        "sentinel.api.app.analysis_service.analyze",
        return_value=result,
    ):
        response = client.post(
            "/analyze",
            json=valid_event_payload(),
        )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == "EVENT_API_TEST"
    assert data["entity_id"] == "USER_00001"

    assert data["risk_score"] == 55.0
    assert data["severity"] == "medium"
    assert data["is_suspicious"] is True

    assert data["anomaly_type"] == "impossible_travel"
    assert data["classification_confidence"] == 0.95
    assert data["classification_evidence"] == [
        "Travel would require impossible speed",
    ]

    assert data["ml_anomaly_score"] == -0.05
    assert data["ml_flagged"] is False
    assert data["ml_contribution"] == 0.0
    assert data["behavioral_contribution"] == 55.0


def test_analyze_rejects_invalid_event() -> None:
    payload = valid_event_payload()

    payload["source_ip"] = "not-an-ip"

    response = client.post(
        "/analyze",
        json=payload,
    )

    assert response.status_code == 422


def test_analyze_rejects_unknown_entity() -> None:
    payload = valid_event_payload()

    payload["entity_id"] = "UNKNOWN_USER"

    response = client.post(
        "/analyze",
        json=payload,
    )

    assert response.status_code == 404

    assert (
        "unknown entity"
        in response.json()["detail"]
    )