from datetime import date

import pytest

from sentinel.domain import ThreatLabel
from sentinel.profiling import EntityProfiler
from sentinel.synthetic import (
    BruteForceInjector,
    NormalEventGenerator,
    PersonaFactory,
)


def build_history(
    user_count: int = 3,
    days: int = 3,
):
    personas = PersonaFactory(
        seed=42
    ).create_users(user_count)

    generator = NormalEventGenerator(seed=42)

    events = []

    for persona in personas:
        for offset in range(days):
            events.extend(
                generator.generate_for_day(
                    persona,
                    date(
                        2026,
                        7,
                        20 + offset,
                    ),
                )
            )

    return personas, events


def test_profiler_builds_profile_per_entity() -> None:
    personas, events = build_history(
        user_count=3,
    )

    profiles = EntityProfiler().build(events)

    assert len(profiles) == 3

    assert {
        persona.entity_id
        for persona in personas
    } == set(profiles)


def test_profile_contains_event_count() -> None:
    personas, events = build_history(
        user_count=1,
    )

    profile = EntityProfiler().build(events)[
        personas[0].entity_id
    ]

    assert profile.event_count == len(events)


def test_profile_learns_known_resources() -> None:
    personas, events = build_history(
        user_count=1,
    )

    profile = EntityProfiler().build(events)[
        personas[0].entity_id
    ]

    observed_resources = {
        event.resource_accessed
        for event in events
    }

    assert profile.known_resources == observed_resources


def test_profile_learns_device_fingerprints() -> None:
    personas, events = build_history(
        user_count=1,
    )

    profile = EntityProfiler().build(events)[
        personas[0].entity_id
    ]

    observed_device_ids = {
        event.device_fingerprint.fingerprint_id
        for event in events
    }

    learned_device_ids = {
        device.fingerprint_id
        for device in profile.known_devices
    }

    assert learned_device_ids == observed_device_ids


def test_profile_statistics_are_valid() -> None:
    personas, events = build_history(
        user_count=1,
    )

    profile = EntityProfiler().build(events)[
        personas[0].entity_id
    ]

    assert 0.0 <= profile.mean_hour <= 23.0
    assert profile.hour_std >= 0.0

    assert profile.mean_session_duration >= 0.0
    assert profile.session_duration_std >= 0.0

    assert (
        0.0
        <= profile.authentication_failure_rate
        <= 1.0
    )


def test_profiler_excludes_attack_events() -> None:
    personas, events = build_history(
        user_count=1,
    )

    persona = personas[0]

    attacked = BruteForceInjector(
        seed=42,
    ).inject(
        events,
        persona,
    )

    attack_count = sum(
        event.label == ThreatLabel.BRUTE_FORCE
        for event in attacked
    )

    assert attack_count > 0

    profile = EntityProfiler().build(attacked)[
        persona.entity_id
    ]

    assert profile.event_count == len(events)


def test_profiler_rejects_empty_history() -> None:
    with pytest.raises(ValueError):
        EntityProfiler().build([])