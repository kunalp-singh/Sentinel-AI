from datetime import date

import pytest

from sentinel.domain import EventOutcome, ThreatLabel
from sentinel.synthetic import (
    BruteForceInjector,
    ImpossibleTravelInjector,
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