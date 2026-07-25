from datetime import UTC, datetime
from ipaddress import ip_address

from sentinel.detection import (
    AnomalyPrediction,
    RiskAssessment,
)
from sentinel.domain import (
    AuthMethod,
    DeviceFingerprint,
    EntityType,
    EventOutcome,
    GeoLocation,
    SecurityEvent,
)
from sentinel.explainability import SecurityExplainer


def build_event() -> SecurityEvent:
    return SecurityEvent(
        event_id="TEST_EVENT_001",
        entity_id="USER_00001",
        entity_type=EntityType.USER,
        timestamp=datetime(
            2026,
            7,
            25,
            7,
            5,
            tzinfo=UTC,
        ),
        source_ip=ip_address("203.0.113.10"),
        geo_location=GeoLocation(
            country_code="AU",
            city="Sydney",
            latitude=-33.8688,
            longitude=151.2093,
        ),
        resource_accessed="internal-api",
        auth_method=AuthMethod.MFA,
        outcome=EventOutcome.SUCCESS,
        session_duration_seconds=300,
        command_sequence=[
            "GET /profile",
        ],
        device_fingerprint=DeviceFingerprint(
            fingerprint_id="device_test_12345678",
            operating_system="macOS",
            browser="Firefox",
            device_type="laptop",
        ),
    )

def build_assessment(
    score: float,
    severity: str,
) -> RiskAssessment:
    return RiskAssessment(
        score=score,
        severity=severity,
        reasons=(
            "Travel between consecutive events "
            "would require 19137 km/h",
            "Consecutive activity occurred 9569 km apart",
        ),
        ml_contribution=0.0,
        behavioral_contribution=score,
    )


def test_explanation_preserves_identity() -> None:
    event = build_event()

    explanation = SecurityExplainer().explain(
        event,
        build_assessment(55.0, "medium"),
        AnomalyPrediction(
            anomaly_score=-0.0614,
            is_anomaly=False,
        ),
    )

    assert explanation.event_id == str(event.event_id)
    assert explanation.entity_id == event.entity_id


def test_explanation_preserves_risk_score() -> None:
    explanation = SecurityExplainer().explain(
        build_event(),
        build_assessment(55.0, "medium"),
        AnomalyPrediction(
            anomaly_score=-0.0614,
            is_anomaly=False,
        ),
    )

    assert explanation.risk_score == 55.0
    assert explanation.severity == "medium"


def test_explanation_contains_reasons() -> None:
    explanation = SecurityExplainer().explain(
        build_event(),
        build_assessment(55.0, "medium"),
        AnomalyPrediction(
            anomaly_score=-0.0614,
            is_anomaly=False,
        ),
    )

    assert len(explanation.reasons) == 2

    assert any(
        "19137" in reason
        for reason in explanation.reasons
    )


def test_explanation_preserves_ml_evidence() -> None:
    explanation = SecurityExplainer().explain(
        build_event(),
        build_assessment(55.0, "medium"),
        AnomalyPrediction(
            anomaly_score=-0.0614,
            is_anomaly=False,
        ),
    )

    assert explanation.ml_anomaly_score == -0.0614
    assert explanation.ml_flagged is False
    assert explanation.ml_contribution == 0.0


def test_medium_summary_is_generated() -> None:
    explanation = SecurityExplainer().explain(
        build_event(),
        build_assessment(55.0, "medium"),
        AnomalyPrediction(
            anomaly_score=-0.0614,
            is_anomaly=False,
        ),
    )

    assert "MEDIUM" in explanation.summary
    assert "55/100" in explanation.summary


def test_critical_summary_recommends_investigation() -> None:
    explanation = SecurityExplainer().explain(
        build_event(),
        build_assessment(90.0, "critical"),
        AnomalyPrediction(
            anomaly_score=0.10,
            is_anomaly=True,
        ),
    )

    assert "CRITICAL" in explanation.summary
    assert "Immediate investigation" in explanation.summary