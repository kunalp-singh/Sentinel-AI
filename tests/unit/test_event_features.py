from datetime import UTC, date, datetime

from sentinel.domain import EventOutcome
from sentinel.features import EventFeatureExtractor
from sentinel.synthetic import (
    NormalEventGenerator,
    PersonaFactory,
)


def build_event():
    persona = PersonaFactory(
        seed=42
    ).create_users(1)[0]

    events = NormalEventGenerator(
        seed=42
    ).generate_for_day(
        persona,
        date(2026, 7, 25),
    )

    return events[0]


def test_extract_returns_expected_identity() -> None:
    event = build_event()

    features = EventFeatureExtractor().extract(event)

    assert features["event_id"] == event.event_id
    assert features["entity_id"] == event.entity_id


def test_extract_temporal_features() -> None:
    event = build_event()

    features = EventFeatureExtractor().extract(event)

    assert features["hour_of_day"] == event.timestamp.hour
    assert features["day_of_week"] == event.timestamp.weekday()
    assert features["is_weekend"] in {0, 1}


def test_weekend_detection() -> None:
    event = build_event()

    event.timestamp = datetime(
        2026,
        7,
        25,
        10,
        30,
        tzinfo=UTC,
    )

    features = EventFeatureExtractor().extract(event)

    assert features["is_weekend"] == 1


def test_auth_failure_feature() -> None:
    event = build_event()
    event.outcome = EventOutcome.FAILURE

    features = EventFeatureExtractor().extract(event)

    assert features["auth_failed"] == 1


def test_command_count() -> None:
    event = build_event()

    event.command_sequence = [
        "AUTHENTICATE",
        "ENUMERATE",
        "ACCESS",
    ]

    features = EventFeatureExtractor().extract(event)

    assert features["command_count"] == 3


def test_location_features() -> None:
    event = build_event()

    features = EventFeatureExtractor().extract(event)

    assert features["latitude"] == event.geo_location.latitude
    assert features["longitude"] == event.geo_location.longitude


def test_device_features() -> None:
    event = build_event()

    features = EventFeatureExtractor().extract(event)

    assert (
        features["operating_system"]
        == event.device_fingerprint.operating_system
    )

    assert (
        features["browser"]
        == event.device_fingerprint.browser
    )


def test_transform_creates_one_row_per_event() -> None:
    persona = PersonaFactory(
        seed=42
    ).create_users(1)[0]

    events = NormalEventGenerator(
        seed=42
    ).generate_for_day(
        persona,
        date(2026, 7, 25),
    )

    dataframe = EventFeatureExtractor().transform(
        events
    )

    assert len(dataframe) == len(events)


def test_transform_contains_expected_columns() -> None:
    event = build_event()

    dataframe = EventFeatureExtractor().transform(
        [event]
    )

    expected = {
        "event_id",
        "entity_id",
        "timestamp",
        "hour_of_day",
        "day_of_week",
        "is_weekend",
        "auth_failed",
        "session_duration_seconds",
        "command_count",
        "latitude",
        "longitude",
        "operating_system",
        "browser",
        "device_type",
        "resource_accessed",
        "auth_method",
        "source_ip",
        "label",
    }

    assert expected.issubset(dataframe.columns)