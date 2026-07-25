from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinel.domain import (
    AuthMethod,
    DeviceFingerprint,
    EntityType,
    EventOutcome,
    GeoLocation,
    RiskScore,
    SecurityEvent,
    Severity,
)


def build_valid_event() -> SecurityEvent:
    return SecurityEvent(
        event_id="EVENT_0001",
        entity_id="USER_0042",
        entity_type=EntityType.USER,
        timestamp=datetime.now(UTC),
        source_ip="192.168.1.20",
        geo_location=GeoLocation(
            country_code="IN",
            city="Bengaluru",
            latitude=12.9716,
            longitude=77.5946,
        ),
        resource_accessed="internal-api",
        auth_method=AuthMethod.MFA,
        outcome=EventOutcome.SUCCESS,
        session_duration_seconds=1800,
        command_sequence=[
            "GET /profile",
            "GET /projects",
        ],
        device_fingerprint=DeviceFingerprint(
            fingerprint_id="device_12345678",
            operating_system="macOS",
            browser="Firefox",
            device_type="laptop",
        ),
    )


def test_valid_security_event() -> None:
    event = build_valid_event()

    assert event.entity_id == "USER_0042"
    assert event.geo_location.country_code == "IN"
    assert event.outcome == EventOutcome.SUCCESS


def test_invalid_ip_is_rejected() -> None:
    with pytest.raises(ValidationError):
        SecurityEvent(
            **{
                **build_valid_event().model_dump(),
                "source_ip": "999.999.999.999",
            }
        )


def test_invalid_latitude_is_rejected() -> None:
    with pytest.raises(ValidationError):
        GeoLocation(
            country_code="IN",
            city="Bengaluru",
            latitude=200,
            longitude=77.5946,
        )


def test_extra_fields_are_rejected() -> None:
    data = build_valid_event().model_dump()

    data["make_me_admin"] = True

    with pytest.raises(ValidationError):
        SecurityEvent(**data)


def test_risk_score_severity_consistency() -> None:
    risk = RiskScore(
        score=91,
        confidence=0.92,
        severity=Severity.CRITICAL,
    )

    assert risk.severity == Severity.CRITICAL


def test_incorrect_risk_severity_is_rejected() -> None:
    with pytest.raises(ValidationError):
        RiskScore(
            score=91,
            confidence=0.92,
            severity=Severity.LOW,
        )