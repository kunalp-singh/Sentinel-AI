from datetime import date

import pytest

from sentinel.domain import EventOutcome, ThreatLabel
from sentinel.synthetic import (
    BruteForceInjector,
    NormalEventGenerator,
    PersonaFactory,
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