from datetime import date

import pytest

from sentinel.domain import EventOutcome, ThreatLabel
from sentinel.synthetic import (
    BruteForceInjector,
    DeviceSpoofingInjector,
    ImpossibleTravelInjector,
    LateralMovementInjector,
    NormalEventGenerator,
    PersonaFactory,
)
from sentinel.synthetic.geo import (
    haversine_distance_km,
    implied_speed_kmh,
)


def build_baseline():
    persona = PersonaFactory(
        seed=42
    ).create_users(1)[0]

    events = NormalEventGenerator(
        seed=42
    ).generate_for_day(
        persona,
        date(2026, 7, 25),
    )

    return persona, events


def test_brute_force_adds_attack_events() -> None:
    persona, events = build_baseline()

    injector = BruteForceInjector(
        seed=42,
        min_attempts=5,
        max_attempts=5,
    )

    result = injector.inject(events, persona)

    assert len(result) == len(events) + 5


def test_brute_force_events_are_labeled() -> None:
    persona, events = build_baseline()

    result = BruteForceInjector(
        seed=42,
        min_attempts=5,
        max_attempts=5,
    ).inject(events, persona)

    attack_events = [
        event
        for event in result
        if event.label == ThreatLabel.BRUTE_FORCE
    ]

    assert len(attack_events) == 5


def test_brute_force_attempts_fail() -> None:
    persona, events = build_baseline()

    result = BruteForceInjector(
        seed=42,
        min_attempts=5,
        max_attempts=5,
    ).inject(events, persona)

    attack_events = [
        event
        for event in result
        if event.label == ThreatLabel.BRUTE_FORCE
    ]

    assert all(
        event.outcome == EventOutcome.FAILURE
        for event in attack_events
    )


def test_brute_force_uses_same_source_ip() -> None:
    persona, events = build_baseline()

    result = BruteForceInjector(
        seed=42,
        min_attempts=5,
        max_attempts=5,
    ).inject(events, persona)

    attack_events = [
        event
        for event in result
        if event.label == ThreatLabel.BRUTE_FORCE
    ]

    source_ips = {
        event.source_ip
        for event in attack_events
    }

    assert len(source_ips) == 1


def test_brute_force_is_temporally_dense() -> None:
    persona, events = build_baseline()

    result = BruteForceInjector(
        seed=42,
        min_attempts=5,
        max_attempts=5,
    ).inject(events, persona)

    attack_events = sorted(
        (
            event
            for event in result
            if event.label == ThreatLabel.BRUTE_FORCE
        ),
        key=lambda event: event.timestamp,
    )

    duration = (
        attack_events[-1].timestamp
        - attack_events[0].timestamp
    )

    assert duration.total_seconds() <= 60


def test_brute_force_rejects_empty_events() -> None:
    persona = PersonaFactory(
        seed=42
    ).create_users(1)[0]

    injector = BruteForceInjector(seed=42)

    with pytest.raises(ValueError):
        injector.inject([], persona)

def test_impossible_travel_adds_one_event() -> None:
    persona, events = build_baseline()

    result = ImpossibleTravelInjector(
        seed=42,
        travel_minutes=30,
    ).inject(events, persona)

    assert len(result) == len(events) + 1


def test_impossible_travel_is_labeled() -> None:
    persona, events = build_baseline()

    result = ImpossibleTravelInjector(
        seed=42,
        travel_minutes=30,
    ).inject(events, persona)

    attack_events = [
        event
        for event in result
        if event.label
        == ThreatLabel.IMPOSSIBLE_TRAVEL
    ]

    assert len(attack_events) == 1


def test_impossible_travel_changes_country() -> None:
    persona, events = build_baseline()

    result = ImpossibleTravelInjector(
        seed=42,
        travel_minutes=30,
    ).inject(events, persona)

    attack_event = next(
        event
        for event in result
        if event.label
        == ThreatLabel.IMPOSSIBLE_TRAVEL
    )

    assert (
        attack_event.geo_location.country_code
        != persona.home_location.country_code
    )


def test_impossible_travel_distance_is_large() -> None:
    persona, events = build_baseline()

    result = ImpossibleTravelInjector(
        seed=42,
        travel_minutes=30,
    ).inject(events, persona)

    attack_event = next(
        event
        for event in result
        if event.label
        == ThreatLabel.IMPOSSIBLE_TRAVEL
    )

    distance = haversine_distance_km(
        persona.home_location,
        attack_event.geo_location,
    )

    assert distance > 3000


def test_impossible_travel_requires_extreme_speed() -> None:
    persona, events = build_baseline()

    result = ImpossibleTravelInjector(
        seed=42,
        travel_minutes=30,
    ).inject(events, persona)

    attack_event = next(
        event
        for event in result
        if event.label
        == ThreatLabel.IMPOSSIBLE_TRAVEL
    )

    persona_events = [
        event
        for event in events
        if event.entity_id == persona.entity_id
        and event.timestamp < attack_event.timestamp
    ]

    anchor = min(
        persona_events,
        key=lambda event: abs(
            (
                attack_event.timestamp
                - event.timestamp
            ).total_seconds()
            - 1800
        ),
    )

    elapsed_seconds = (
        attack_event.timestamp
        - anchor.timestamp
    ).total_seconds()

    speed = implied_speed_kmh(
        anchor.geo_location,
        attack_event.geo_location,
        elapsed_seconds,
    )

    assert speed > 1000


def test_implied_speed_rejects_zero_time() -> None:
    persona, _ = build_baseline()

    with pytest.raises(ValueError):
        implied_speed_kmh(
            persona.home_location,
            persona.home_location,
            0,
        )


def get_lateral_events(events):
    return [
        event
        for event in events
        if event.label
        == ThreatLabel.LATERAL_MOVEMENT
    ]


def test_lateral_movement_adds_sequence() -> None:
    persona, events = build_baseline()

    result = LateralMovementInjector(
        seed=42,
    ).inject(events, persona)

    attacks = get_lateral_events(result)

    assert len(attacks) >= 3


def test_lateral_movement_accesses_novel_resources() -> None:
    persona, events = build_baseline()

    result = LateralMovementInjector(
        seed=42,
    ).inject(events, persona)

    attacks = get_lateral_events(result)

    assert all(
        event.resource_accessed
        not in persona.common_resources
        for event in attacks
    )


def test_lateral_movement_is_successful() -> None:
    persona, events = build_baseline()

    result = LateralMovementInjector(
        seed=42,
    ).inject(events, persona)

    attacks = get_lateral_events(result)

    assert all(
        event.outcome == EventOutcome.SUCCESS
        for event in attacks
    )


def test_lateral_movement_is_temporally_dense() -> None:
    persona, events = build_baseline()

    result = LateralMovementInjector(
        seed=42,
        interval_minutes=3,
    ).inject(events, persona)

    attacks = sorted(
        get_lateral_events(result),
        key=lambda event: event.timestamp,
    )

    duration = (
        attacks[-1].timestamp
        - attacks[0].timestamp
    )

    assert duration.total_seconds() <= 15 * 60


def test_lateral_movement_preserves_source_ip() -> None:
    persona, events = build_baseline()

    result = LateralMovementInjector(
        seed=42,
    ).inject(events, persona)

    attacks = get_lateral_events(result)

    normal_ips = {
        event.source_ip
        for event in events
    }

    assert all(
        event.source_ip in normal_ips
        for event in attacks
    )


def test_lateral_movement_preserves_known_device() -> None:
    persona, events = build_baseline()

    result = LateralMovementInjector(
        seed=42,
    ).inject(events, persona)

    attacks = get_lateral_events(result)

    assert all(
        event.device_fingerprint.fingerprint_id
        in persona.known_device_ids
        for event in attacks
    )


def test_lateral_movement_reaches_sensitive_resource() -> None:
    persona, events = build_baseline()

    result = LateralMovementInjector(
        seed=42,
    ).inject(events, persona)

    attacks = get_lateral_events(result)

    resources = {
        event.resource_accessed
        for event in attacks
    }

    assert "secrets-vault" in resources


def test_lateral_movement_rejects_empty_events() -> None:
    persona = PersonaFactory(
        seed=42
    ).create_users(1)[0]

    injector = LateralMovementInjector(seed=42)

    with pytest.raises(ValueError):
        injector.inject([], persona)

def get_device_spoofing_events(events):
    return [
        event
        for event in events
        if event.label
        == ThreatLabel.DEVICE_SPOOFING
    ]


def test_device_spoofing_adds_one_event() -> None:
    persona, events = build_baseline()

    result = DeviceSpoofingInjector(
        seed=42,
    ).inject(events, persona)

    attacks = get_device_spoofing_events(result)

    assert len(attacks) == 1
    assert len(result) == len(events) + 1


def test_device_spoofing_reuses_device_id() -> None:
    persona, events = build_baseline()

    result = DeviceSpoofingInjector(
        seed=42,
    ).inject(events, persona)

    attack = get_device_spoofing_events(result)[0]

    known_ids = {
        event.device_fingerprint.fingerprint_id
        for event in events
    }

    assert (
        attack.device_fingerprint.fingerprint_id
        in known_ids
    )


def test_device_spoofing_changes_fingerprint() -> None:
    persona, events = build_baseline()

    result = DeviceSpoofingInjector(
        seed=42,
    ).inject(events, persona)

    attack = get_device_spoofing_events(result)[0]

    original = next(
        event.device_fingerprint
        for event in events
        if (
            event.device_fingerprint.fingerprint_id
            == attack.device_fingerprint.fingerprint_id
        )
    )

    assert (
        attack.device_fingerprint.operating_system
        != original.operating_system
        or attack.device_fingerprint.browser
        != original.browser
        or attack.device_fingerprint.device_type
        != original.device_type
    )


def test_device_spoofing_preserves_source_ip() -> None:
    persona, events = build_baseline()

    result = DeviceSpoofingInjector(
        seed=42,
    ).inject(events, persona)

    attack = get_device_spoofing_events(result)[0]

    matching_events = [
        event
        for event in events
        if (
            event.device_fingerprint.fingerprint_id
            == attack.device_fingerprint.fingerprint_id
        )
    ]

    assert any(
        event.source_ip == attack.source_ip
        for event in matching_events
    )

def test_device_spoofing_preserves_location() -> None:
    persona, events = build_baseline()

    result = DeviceSpoofingInjector(
        seed=42,
    ).inject(events, persona)

    attack = get_device_spoofing_events(result)[0]

    known_locations = {
        (
            event.geo_location.latitude,
            event.geo_location.longitude,
        )
        for event in events
    }

    attack_location = (
        attack.geo_location.latitude,
        attack.geo_location.longitude,
    )

    assert attack_location in known_locations


def test_device_spoofing_is_successful() -> None:
    persona, events = build_baseline()

    result = DeviceSpoofingInjector(
        seed=42,
    ).inject(events, persona)

    attack = get_device_spoofing_events(result)[0]

    assert attack.outcome == EventOutcome.SUCCESS


def test_device_spoofing_rejects_empty_events() -> None:
    persona = PersonaFactory(
        seed=42
    ).create_users(1)[0]

    with pytest.raises(ValueError):
        DeviceSpoofingInjector(
            seed=42
        ).inject([], persona)