from datetime import date, timedelta

import numpy as np
import pytest

from sentinel.detection import IsolationForestDetector
from sentinel.features import (
    MODEL_FEATURES,
    FeatureMatrixBuilder,
)
from sentinel.profiling import EntityProfiler
from sentinel.synthetic import (
    ImpossibleTravelInjector,
    NormalEventGenerator,
    PersonaFactory,
)


def build_training_matrix():
    personas = PersonaFactory(
        seed=42
    ).create_users(5)

    generator = NormalEventGenerator(seed=42)

    history = []
    training = []

    start = date(2026, 7, 10)

    for persona in personas:
        for offset in range(5):
            history.extend(
                generator.generate_for_day(
                    persona,
                    start + timedelta(days=offset),
                )
            )

        for offset in range(5, 8):
            training.extend(
                generator.generate_for_day(
                    persona,
                    start + timedelta(days=offset),
                )
            )

    profiles = EntityProfiler().build(history)

    matrix = FeatureMatrixBuilder().build(
        training,
        profiles,
    )

    return matrix, personas, profiles, generator


def test_detector_can_be_fitted() -> None:
    matrix, _, _, _ = build_training_matrix()

    detector = IsolationForestDetector()

    detector.fit(matrix.X)

    assert detector.is_fitted


def test_detector_returns_prediction_per_row() -> None:
    matrix, _, _, _ = build_training_matrix()

    detector = IsolationForestDetector()
    detector.fit(matrix.X)

    predictions = detector.predict(matrix.X)

    assert len(predictions) == len(matrix.X)


def test_anomaly_scores_are_finite() -> None:
    matrix, _, _, _ = build_training_matrix()

    detector = IsolationForestDetector()
    detector.fit(matrix.X)

    scores = detector.anomaly_scores(matrix.X)

    assert len(scores) == len(matrix.X)
    assert np.isfinite(scores).all()


def test_prediction_contains_boolean_flag() -> None:
    matrix, _, _, _ = build_training_matrix()

    detector = IsolationForestDetector()
    detector.fit(matrix.X)

    prediction = detector.predict(
        matrix.X.iloc[:1]
    )[0]

    assert isinstance(
        prediction.is_anomaly,
        bool,
    )


def test_predict_before_fit_is_rejected() -> None:
    matrix, _, _, _ = build_training_matrix()

    detector = IsolationForestDetector()

    with pytest.raises(RuntimeError):
        detector.predict(matrix.X)


def test_invalid_contamination_is_rejected() -> None:
    with pytest.raises(ValueError):
        IsolationForestDetector(
            contamination=0.0,
        )

    with pytest.raises(ValueError):
        IsolationForestDetector(
            contamination=0.8,
        )


def test_missing_features_are_rejected() -> None:
    matrix, _, _, _ = build_training_matrix()

    detector = IsolationForestDetector()

    invalid = matrix.X.drop(
        columns=[MODEL_FEATURES[0]]
    )

    with pytest.raises(ValueError):
        detector.fit(invalid)


def test_missing_values_are_rejected() -> None:
    matrix, _, _, _ = build_training_matrix()

    invalid = matrix.X.copy()

    invalid.iloc[0, 0] = np.nan

    detector = IsolationForestDetector()

    with pytest.raises(ValueError):
        detector.fit(invalid)


def test_impossible_travel_scores_more_anomalous_than_typical_event() -> None:
    (
        training_matrix,
        personas,
        profiles,
        generator,
    ) = build_training_matrix()

    detector = IsolationForestDetector(
        contamination=0.01,
    )

    detector.fit(training_matrix.X)

    persona = personas[0]

    normal_events = generator.generate_for_day(
        persona,
        date(2026, 7, 20),
    )

    attacked_events = ImpossibleTravelInjector(
        seed=42,
    ).inject(
        normal_events,
        persona,
    )

    evaluation_matrix = FeatureMatrixBuilder().build(
        attacked_events,
        profiles,
    )

    scores = detector.anomaly_scores(
        evaluation_matrix.X
    )

    labels = evaluation_matrix.y

    attack_scores = scores[
        labels.to_numpy() == "impossible_travel"
    ]

    normal_scores = scores[
        labels.to_numpy() == "normal"
    ]

    assert len(attack_scores) > 0
    assert len(normal_scores) > 0

    assert float(np.max(attack_scores)) > float(
        np.median(normal_scores)
    )