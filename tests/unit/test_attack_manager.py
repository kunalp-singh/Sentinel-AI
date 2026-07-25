from datetime import date

import pytest

from sentinel.domain import ThreatLabel
from sentinel.synthetic import (
    AttackRateManager,
    BruteForceInjector,
    NormalEventGenerator,
    PersonaFactory,
    SyntheticDatasetBuilder,
)


def build_dataset():
    personas = PersonaFactory(
        seed=42
    ).create_users(100)

    builder = SyntheticDatasetBuilder(
        NormalEventGenerator(seed=42)
    )

    events = builder.generate_normal_dataset(
        personas=personas,
        start_date=date(2026, 7, 1),
        days=30,
    )

    return personas, events


def test_attack_rate_is_close_to_target() -> None:
    personas, events = build_dataset()

    result = AttackRateManager(seed=42).inject(
        events=events,
        personas=personas,
        injector=BruteForceInjector(
            seed=42,
            min_attempts=6,
            max_attempts=6,
        ),
        target_rate=0.01,
    )

    assert result.injected_event_count > 0

    assert abs(
        result.anomaly_rate - 0.01
    ) <= 0.001


def test_attack_manager_preserves_normal_events() -> None:
    personas, events = build_dataset()

    result = AttackRateManager(seed=42).inject(
        events=events,
        personas=personas,
        injector=BruteForceInjector(
            seed=42,
            min_attempts=6,
            max_attempts=6,
        ),
        target_rate=0.01,
    )

    normal_count = sum(
        event.label == ThreatLabel.NORMAL
        for event in result.events
    )

    assert normal_count == len(events)


def test_attack_manager_reports_attacked_entities() -> None:
    personas, events = build_dataset()

    result = AttackRateManager(seed=42).inject(
        events=events,
        personas=personas,
        injector=BruteForceInjector(
            seed=42,
            min_attempts=6,
            max_attempts=6,
        ),
        target_rate=0.01,
    )

    assert result.attacked_entity_count > 0


@pytest.mark.parametrize(
    "invalid_rate",
    [
        0.0,
        0.004,
        0.031,
        0.50,
    ],
)
def test_invalid_attack_rates_are_rejected(
    invalid_rate: float,
) -> None:
    personas, events = build_dataset()

    manager = AttackRateManager(seed=42)

    with pytest.raises(ValueError):
        manager.inject(
            events=events,
            personas=personas,
            injector=BruteForceInjector(seed=42),
            target_rate=invalid_rate,
        )


def test_manager_rejects_already_attacked_dataset() -> None:
    personas, events = build_dataset()

    injector = BruteForceInjector(
        seed=42,
        min_attempts=5,
        max_attempts=5,
    )

    attacked = injector.inject(
        events,
        personas[0],
    )

    manager = AttackRateManager(seed=42)

    with pytest.raises(ValueError):
        manager.inject(
            events=attacked,
            personas=personas,
            injector=injector,
            target_rate=0.01,
        )