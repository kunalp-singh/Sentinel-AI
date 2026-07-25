from datetime import date

from sentinel.domain import ThreatLabel
from sentinel.synthetic import (
    NormalEventGenerator,
    PersonaFactory,
    SyntheticDatasetBuilder,
)


def test_persona_factory_creates_requested_users() -> None:
    factory = PersonaFactory(seed=42)

    personas = factory.create_users(10)

    assert len(personas) == 10
    assert len(
        {persona.entity_id for persona in personas}
    ) == 10


def test_persona_generation_is_reproducible() -> None:
    first = PersonaFactory(seed=42).create_users(5)
    second = PersonaFactory(seed=42).create_users(5)

    assert first == second


def test_normal_events_use_known_devices() -> None:
    persona = PersonaFactory(
        seed=42
    ).create_users(1)[0]

    generator = NormalEventGenerator(seed=42)

    events = generator.generate_for_day(
        persona,
        date(2026, 7, 25),
    )

    assert events

    for event in events:
        assert (
            event.device_fingerprint.fingerprint_id
            in persona.known_device_ids
        )


def test_normal_events_have_normal_label() -> None:
    persona = PersonaFactory(
        seed=42
    ).create_users(1)[0]

    events = NormalEventGenerator(
        seed=42
    ).generate_for_day(
        persona,
        date(2026, 7, 25),
    )

    assert all(
        event.label == ThreatLabel.NORMAL
        for event in events
    )


def test_dataset_builder_generates_dataframe() -> None:
    personas = PersonaFactory(
        seed=42
    ).create_users(5)

    generator = NormalEventGenerator(seed=42)

    builder = SyntheticDatasetBuilder(
        generator
    )

    events = builder.generate_normal_dataset(
        personas=personas,
        start_date=date(2026, 7, 1),
        days=7,
    )

    dataframe = builder.to_dataframe(events)

    assert not dataframe.empty
    assert len(dataframe) == len(events)

    assert {
        "entity_id",
        "timestamp",
        "source_ip",
        "resource_accessed",
        "label",
    }.issubset(dataframe.columns)