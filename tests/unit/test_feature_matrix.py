from datetime import date, timedelta

import numpy as np
import pytest

from sentinel.features import (
    MODEL_FEATURES,
    FeatureMatrixBuilder,
)
from sentinel.profiling import EntityProfiler
from sentinel.synthetic import (
    NormalEventGenerator,
    PersonaFactory,
)


def build_matrix_data():
    personas = PersonaFactory(
        seed=42
    ).create_users(2)

    generator = NormalEventGenerator(seed=42)

    history = []
    evaluation = []

    start = date(2026, 7, 20)

    for persona in personas:
        for offset in range(3):
            history.extend(
                generator.generate_for_day(
                    persona,
                    start + timedelta(days=offset),
                )
            )

        evaluation.extend(
            generator.generate_for_day(
                persona,
                date(2026, 7, 23),
            )
        )

    profiles = EntityProfiler().build(history)

    return evaluation, profiles


def test_matrix_has_one_row_per_event() -> None:
    events, profiles = build_matrix_data()

    matrix = FeatureMatrixBuilder().build(
        events,
        profiles,
    )

    assert len(matrix.X) == len(events)
    assert len(matrix.y) == len(events)
    assert len(matrix.metadata) == len(events)


def test_matrix_contains_only_model_features() -> None:
    events, profiles = build_matrix_data()

    matrix = FeatureMatrixBuilder().build(
        events,
        profiles,
    )

    assert tuple(matrix.X.columns) == MODEL_FEATURES


def test_matrix_does_not_contain_label() -> None:
    events, profiles = build_matrix_data()

    matrix = FeatureMatrixBuilder().build(
        events,
        profiles,
    )

    assert "label" not in matrix.X.columns


def test_matrix_does_not_contain_identifiers() -> None:
    events, profiles = build_matrix_data()

    matrix = FeatureMatrixBuilder().build(
        events,
        profiles,
    )

    forbidden = {
        "event_id",
        "entity_id",
        "timestamp",
        "source_ip",
    }

    assert forbidden.isdisjoint(matrix.X.columns)


def test_matrix_is_numeric() -> None:
    events, profiles = build_matrix_data()

    matrix = FeatureMatrixBuilder().build(
        events,
        profiles,
    )

    assert all(
        np.issubdtype(dtype, np.number)
        for dtype in matrix.X.dtypes
    )


def test_matrix_has_no_missing_values() -> None:
    events, profiles = build_matrix_data()

    matrix = FeatureMatrixBuilder().build(
        events,
        profiles,
    )

    assert not matrix.X.isna().any().any()


def test_metadata_preserves_identity() -> None:
    events, profiles = build_matrix_data()

    matrix = FeatureMatrixBuilder().build(
        events,
        profiles,
    )

    assert {
        "event_id",
        "entity_id",
        "timestamp",
    }.issubset(matrix.metadata.columns)


def test_labels_are_separate() -> None:
    events, profiles = build_matrix_data()

    matrix = FeatureMatrixBuilder().build(
        events,
        profiles,
    )

    assert matrix.y.name == "label"
    assert "label" not in matrix.X.columns


def test_missing_profile_is_rejected() -> None:
    events, _ = build_matrix_data()

    with pytest.raises(
        ValueError,
        match="missing behavioral profile",
    ):
        FeatureMatrixBuilder().build(
            events,
            {},
        )


def test_empty_events_are_rejected() -> None:
    with pytest.raises(ValueError):
        FeatureMatrixBuilder().build(
            [],
            {},
        )