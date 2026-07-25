from datetime import date

import pytest

from sentinel.domain import EventOutcome, ThreatLabel
from sentinel.synthetic import (
    CredentialStuffingInjector,
    NormalEventGenerator,
    PersonaFactory,
    SyntheticDatasetBuilder,
)


def build_campaign_baseline():
    personas = PersonaFactory(
        seed=42
    ).create_users(20)

    builder = SyntheticDatasetBuilder(
        NormalEventGenerator(seed=42)
    )

    events = builder.generate_normal_dataset(
        personas=personas,
        start_date=date(2026, 7, 25),
        days=1,
    )

    return personas, events


def get_attack_events(events):
    return [
        event
        for event in events
        if event.label
        == ThreatLabel.CREDENTIAL_STUFFING
    ]


def test_credential_stuffing_targets_multiple_users() -> None:
    personas, events = build_campaign_baseline()

    result = CredentialStuffingInjector(
        seed=42,
        min_targets=8,
        max_targets=8,
    ).inject(events, personas)

    attacks = get_attack_events(result)

    targeted_entities = {
        event.entity_id
        for event in attacks
    }

    assert len(attacks) == 8
    assert len(targeted_entities) == 8


def test_credential_stuffing_uses_same_source_ip() -> None:
    personas, events = build_campaign_baseline()

    result = CredentialStuffingInjector(
        seed=42,
        min_targets=8,
        max_targets=8,
    ).inject(events, personas)

    attacks = get_attack_events(result)

    source_ips = {
        event.source_ip
        for event in attacks
    }

    assert len(source_ips) == 1


def test_credential_stuffing_is_temporally_dense() -> None:
    personas, events = build_campaign_baseline()

    result = CredentialStuffingInjector(
        seed=42,
        min_targets=8,
        max_targets=8,
    ).inject(events, personas)

    attacks = sorted(
        get_attack_events(result),
        key=lambda event: event.timestamp,
    )

    duration = (
        attacks[-1].timestamp
        - attacks[0].timestamp
    )

    assert duration.total_seconds() <= 120


def test_credential_stuffing_uses_password_auth() -> None:
    personas, events = build_campaign_baseline()

    result = CredentialStuffingInjector(
        seed=42,
        min_targets=8,
        max_targets=8,
    ).inject(events, personas)

    attacks = get_attack_events(result)

    assert all(
        event.auth_method.value == "password"
        for event in attacks
    )


def test_zero_success_rate_produces_failures() -> None:
    personas, events = build_campaign_baseline()

    result = CredentialStuffingInjector(
        seed=42,
        min_targets=8,
        max_targets=8,
        success_rate=0.0,
    ).inject(events, personas)

    attacks = get_attack_events(result)

    assert all(
        event.outcome == EventOutcome.FAILURE
        for event in attacks
    )


def test_full_success_rate_produces_successes() -> None:
    personas, events = build_campaign_baseline()

    result = CredentialStuffingInjector(
        seed=42,
        min_targets=8,
        max_targets=8,
        success_rate=1.0,
    ).inject(events, personas)

    attacks = get_attack_events(result)

    assert all(
        event.outcome == EventOutcome.SUCCESS
        for event in attacks
    )


def test_credential_stuffing_rejects_too_few_personas() -> None:
    personas, events = build_campaign_baseline()

    injector = CredentialStuffingInjector(
        seed=42,
        min_targets=5,
    )

    with pytest.raises(ValueError):
        injector.inject(
            events,
            personas[:2],
        )