from datetime import date, timedelta

from sentinel.detection import IsolationForestDetector
from sentinel.evaluation import DetectorEvaluator
from sentinel.features import FeatureMatrixBuilder
from sentinel.profiling import EntityProfiler
from sentinel.synthetic import (
    BruteForceInjector,
    NormalEventGenerator,
    PersonaFactory,
)


def build_evaluation_data():
    personas = PersonaFactory(
        seed=42
    ).create_users(5)

    generator = NormalEventGenerator(seed=42)

    history = []
    training = []

    start = date(2026, 7, 1)

    for persona in personas:
        for offset in range(5):
            history.extend(
                generator.generate_for_day(
                    persona,
                    start + timedelta(days=offset),
                )
            )

        for offset in range(5, 10):
            training.extend(
                generator.generate_for_day(
                    persona,
                    start + timedelta(days=offset),
                )
            )

    profiles = EntityProfiler().build(history)

    builder = FeatureMatrixBuilder()

    training_matrix = builder.build(
        training,
        profiles,
    )

    detector = IsolationForestDetector(
        contamination=0.01,
        random_state=42,
    )

    detector.fit(training_matrix.X)

    target = personas[0]

    evaluation_events = generator.generate_for_day(
        target,
        date(2026, 7, 20),
    )

    evaluation_events = BruteForceInjector(
        seed=42,
    ).inject(
        evaluation_events,
        target,
    )

    evaluation_matrix = builder.build(
        evaluation_events,
        profiles,
    )

    return detector, evaluation_matrix


def test_evaluator_returns_valid_metrics() -> None:
    detector, matrix = build_evaluation_data()

    result = DetectorEvaluator().evaluate(
        detector,
        matrix,
    )

    assert 0.0 <= result.precision <= 1.0
    assert 0.0 <= result.recall <= 1.0
    assert 0.0 <= result.f1_score <= 1.0
    assert 0.0 <= result.false_positive_rate <= 1.0


def test_confusion_matrix_accounts_for_all_events() -> None:
    detector, matrix = build_evaluation_data()

    result = DetectorEvaluator().evaluate(
        detector,
        matrix,
    )

    total = (
        result.true_positives
        + result.false_positives
        + result.true_negatives
        + result.false_negatives
    )

    assert total == len(matrix.X)


def test_attack_metrics_are_generated() -> None:
    detector, matrix = build_evaluation_data()

    result = DetectorEvaluator().evaluate(
        detector,
        matrix,
    )

    assert len(result.attack_metrics) > 0

    attack_types = {
        metric.attack_type
        for metric in result.attack_metrics
    }

    assert "brute_force" in attack_types


def test_attack_detection_rate_is_bounded() -> None:
    detector, matrix = build_evaluation_data()

    result = DetectorEvaluator().evaluate(
        detector,
        matrix,
    )

    for metric in result.attack_metrics:
        assert 0.0 <= metric.detection_rate <= 1.0


def test_attack_counts_are_consistent() -> None:
    detector, matrix = build_evaluation_data()

    result = DetectorEvaluator().evaluate(
        detector,
        matrix,
    )

    for metric in result.attack_metrics:
        assert metric.detected <= metric.total