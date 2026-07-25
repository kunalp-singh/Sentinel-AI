from datetime import date

import pytest

from sentinel.domain import DeviceFingerprint
from sentinel.features import ProfileDeviationExtractor
from sentinel.profiling import EntityProfiler
from sentinel.synthetic import (
    NormalEventGenerator,
    PersonaFactory,
)


def build_event_and_profile():
    persona = PersonaFactory(
        seed=42
    ).create_users(1)[0]

    generator = NormalEventGenerator(seed=42)

    events = []

    for day in range(20, 23):
        events.extend(
            generator.generate_for_day(
                persona,
                date(2026, 7, day),
            )
        )

    profile = EntityProfiler().build(events)[
        persona.entity_id
    ]

    return events[0], profile


def test_known_event_has_known_context() -> None:
    event, profile = build_event_and_profile()

    features = ProfileDeviationExtractor().extract(
        event,
        profile,
    )

    assert features["is_new_ip"] == 0
    assert features["is_new_resource"] == 0
    assert features["is_new_device"] == 0


def test_new_ip_is_detected() -> None:
    event, profile = build_event_and_profile()

    event.source_ip = "203.0.113.200"

    features = ProfileDeviationExtractor().extract(
        event,
        profile,
    )

    assert features["is_new_ip"] == 1


def test_new_resource_is_detected() -> None:
    event, profile = build_event_and_profile()

    event.resource_accessed = "secrets-vault"

    features = ProfileDeviationExtractor().extract(
        event,
        profile,
    )

    assert features["is_new_resource"] == 1


def test_new_device_is_detected() -> None:
    event, profile = build_event_and_profile()

    event.device_fingerprint = DeviceFingerprint(
        fingerprint_id="totally_new_device",
        operating_system="Linux",
        browser="Firefox",
        device_type="laptop",
    )

    features = ProfileDeviationExtractor().extract(
        event,
        profile,
    )

    assert features["is_new_device"] == 1
    assert (
        features["device_fingerprint_mismatch"]
        == 0
    )


def test_known_device_with_changed_fingerprint_is_detected() -> None:
    event, profile = build_event_and_profile()

    known_id = (
        event.device_fingerprint.fingerprint_id
    )

    event.device_fingerprint = DeviceFingerprint(
        fingerprint_id=known_id,
        operating_system="Android",
        browser="Chrome Mobile",
        device_type="mobile",
    )

    features = ProfileDeviationExtractor().extract(
        event,
        profile,
    )

    assert features["is_new_device"] == 0
    assert (
        features["device_fingerprint_mismatch"]
        == 1
    )


def test_normal_fingerprint_does_not_mismatch() -> None:
    event, profile = build_event_and_profile()

    features = ProfileDeviationExtractor().extract(
        event,
        profile,
    )

    assert (
        features["device_fingerprint_mismatch"]
        == 0
    )


def test_hour_deviation_is_non_negative() -> None:
    event, profile = build_event_and_profile()

    features = ProfileDeviationExtractor().extract(
        event,
        profile,
    )

    assert features["hour_deviation"] >= 0.0
    assert features["hour_deviation"] <= 12.0


def test_session_deviation_is_non_negative() -> None:
    event, profile = build_event_and_profile()

    features = ProfileDeviationExtractor().extract(
        event,
        profile,
    )

    assert (
        features["session_duration_deviation"]
        >= 0.0
    )


def test_wrong_entity_profile_is_rejected() -> None:
    event, profile = build_event_and_profile()

    wrong_profile = profile.model_copy(
        update={
            "entity_id": "USER_DIFFERENT",
        }
    )

    with pytest.raises(ValueError):
        ProfileDeviationExtractor().extract(
            event,
            wrong_profile,
        )