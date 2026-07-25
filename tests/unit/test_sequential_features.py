from datetime import date

from sentinel.domain import ThreatLabel
from sentinel.features import SequentialFeatureExtractor
from sentinel.synthetic import (
    BruteForceInjector,
    CredentialStuffingInjector,
    ImpossibleTravelInjector,
    LateralMovementInjector,
    NormalEventGenerator,
    PersonaFactory,
)


def build_baseline(
    user_count: int = 1,
):
    personas = PersonaFactory(
        seed=42
    ).create_users(user_count)

    generator = NormalEventGenerator(seed=42)

    events = []

    for persona in personas:
        events.extend(
            generator.generate_for_day(
                persona,
                date(2026, 7, 25),
            )
        )

    return personas, events


def test_first_event_has_zero_travel_features() -> None:
    _, events = build_baseline()

    first = min(
        events,
        key=lambda event: event.timestamp,
    )

    features = SequentialFeatureExtractor().extract(
        first,
        events,
    )

    assert features["distance_from_previous_km"] == 0.0
    assert features["implied_speed_kmh"] == 0.0


def test_brute_force_has_multiple_recent_failures() -> None:
    personas, events = build_baseline()

    attacked = BruteForceInjector(
        seed=42,
    ).inject(
        events,
        personas[0],
    )

    attack_events = [
        event
        for event in attacked
        if event.label == ThreatLabel.BRUTE_FORCE
    ]

    final_attack = max(
        attack_events,
        key=lambda event: event.timestamp,
    )

    features = SequentialFeatureExtractor().extract(
        final_attack,
        attacked,
    )

    assert features["failed_logins_10m"] >= 2
    assert features["events_10m"] >= 2


def test_impossible_travel_has_large_distance() -> None:
    personas, events = build_baseline()

    attacked = ImpossibleTravelInjector(
        seed=42,
    ).inject(
        events,
        personas[0],
    )

    attack = next(
        event
        for event in attacked
        if event.label == ThreatLabel.IMPOSSIBLE_TRAVEL
    )

    features = SequentialFeatureExtractor().extract(
        attack,
        attacked,
    )

    assert features["distance_from_previous_km"] > 1000.0


def test_impossible_travel_has_extreme_speed() -> None:
    personas, events = build_baseline()

    attacked = ImpossibleTravelInjector(
        seed=42,
    ).inject(
        events,
        personas[0],
    )

    attack = next(
        event
        for event in attacked
        if event.label == ThreatLabel.IMPOSSIBLE_TRAVEL
    )

    features = SequentialFeatureExtractor().extract(
        attack,
        attacked,
    )

    assert features["implied_speed_kmh"] > 1000.0


def test_lateral_movement_accesses_multiple_resources() -> None:
    personas, events = build_baseline()

    attacked = LateralMovementInjector(
        seed=42,
    ).inject(
        events,
        personas[0],
    )

    attack_events = [
        event
        for event in attacked
        if event.label == ThreatLabel.LATERAL_MOVEMENT
    ]

    final_attack = max(
        attack_events,
        key=lambda event: event.timestamp,
    )

    features = SequentialFeatureExtractor().extract(
        final_attack,
        attacked,
    )

    assert features["unique_resources_30m"] >= 2
    assert features["resource_access_velocity_30m"] > 0.0


def test_credential_stuffing_has_entity_fanout() -> None:
    personas, events = build_baseline(
        user_count=10,
    )

    attacked = CredentialStuffingInjector(
        seed=42,
    ).inject(
        events,
        personas,
    )

    attack_events = [
        event
        for event in attacked
        if event.label
        == ThreatLabel.CREDENTIAL_STUFFING
    ]

    final_attack = max(
        attack_events,
        key=lambda event: event.timestamp,
    )

    features = SequentialFeatureExtractor().extract(
        final_attack,
        attacked,
    )

    assert features["source_ip_entity_fanout_10m"] >= 2


def test_window_does_not_use_future_events() -> None:
    _, events = build_baseline()

    ordered = sorted(
        events,
        key=lambda event: event.timestamp,
    )

    first = ordered[0]

    features_with_all_events = (
        SequentialFeatureExtractor().extract(
            first,
            ordered,
        )
    )

    events_up_to_first = [
        event
        for event in ordered
        if event.timestamp <= first.timestamp
    ]

    features_without_future = (
        SequentialFeatureExtractor().extract(
            first,
            events_up_to_first,
        )
    )

    assert (
        features_with_all_events["events_10m"]
        == features_without_future["events_10m"]
    )

    assert (
        features_with_all_events["failed_logins_10m"]
        == features_without_future["failed_logins_10m"]
    )