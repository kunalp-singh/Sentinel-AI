from dataclasses import dataclass

import numpy as np

from sentinel.detection import IsolationForestDetector
from sentinel.features import FeatureMatrix


@dataclass(frozen=True)
class AttackMetrics:
    """Detection statistics for one attack type."""

    attack_type: str
    total: int
    detected: int
    detection_rate: float
    mean_anomaly_score: float


@dataclass(frozen=True)
class EvaluationResult:
    """Overall anomaly-detection evaluation results."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float

    attack_metrics: tuple[AttackMetrics, ...]


class DetectorEvaluator:
    """Evaluate SentinelAI anomaly detection against synthetic labels."""

    NORMAL_LABEL = "normal"

    def evaluate(
        self,
        detector: IsolationForestDetector,
        matrix: FeatureMatrix,
    ) -> EvaluationResult:
        if len(matrix.X) == 0:
            raise ValueError(
                "cannot evaluate an empty feature matrix"
            )

        if len(matrix.X) != len(matrix.y):
            raise ValueError(
                "feature and label counts do not match"
            )

        predictions = detector.predict(matrix.X)

        predicted_anomaly = np.asarray(
            [
                prediction.is_anomaly
                for prediction in predictions
            ],
            dtype=bool,
        )

        scores = np.asarray(
            [
                prediction.anomaly_score
                for prediction in predictions
            ],
            dtype=np.float64,
        )

        labels = matrix.y.astype(str).to_numpy()

        actual_anomaly = labels != self.NORMAL_LABEL

        true_positives = int(
            np.sum(
                predicted_anomaly
                & actual_anomaly
            )
        )

        false_positives = int(
            np.sum(
                predicted_anomaly
                & ~actual_anomaly
            )
        )

        true_negatives = int(
            np.sum(
                ~predicted_anomaly
                & ~actual_anomaly
            )
        )

        false_negatives = int(
            np.sum(
                ~predicted_anomaly
                & actual_anomaly
            )
        )

        precision = self._safe_divide(
            true_positives,
            true_positives + false_positives,
        )

        recall = self._safe_divide(
            true_positives,
            true_positives + false_negatives,
        )

        f1_score = self._safe_divide(
            2.0 * precision * recall,
            precision + recall,
        )

        false_positive_rate = self._safe_divide(
            false_positives,
            false_positives + true_negatives,
        )

        attack_metrics = self._attack_metrics(
            labels,
            predicted_anomaly,
            scores,
        )

        return EvaluationResult(
            true_positives=true_positives,
            false_positives=false_positives,
            true_negatives=true_negatives,
            false_negatives=false_negatives,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            false_positive_rate=false_positive_rate,
            attack_metrics=attack_metrics,
        )

    def _attack_metrics(
        self,
        labels: np.ndarray,
        predicted_anomaly: np.ndarray,
        scores: np.ndarray,
    ) -> tuple[AttackMetrics, ...]:
        metrics: list[AttackMetrics] = []

        attack_labels = sorted(
            {
                str(label)
                for label in labels
                if str(label) != self.NORMAL_LABEL
            }
        )

        for attack_label in attack_labels:
            mask = labels == attack_label

            total = int(np.sum(mask))

            detected = int(
                np.sum(
                    predicted_anomaly[mask]
                )
            )

            detection_rate = self._safe_divide(
                detected,
                total,
            )

            mean_score = float(
                np.mean(scores[mask])
            )

            metrics.append(
                AttackMetrics(
                    attack_type=attack_label,
                    total=total,
                    detected=detected,
                    detection_rate=detection_rate,
                    mean_anomaly_score=mean_score,
                )
            )

        return tuple(metrics)

    @staticmethod
    def _safe_divide(
        numerator: float,
        denominator: float,
    ) -> float:
        if denominator == 0:
            return 0.0

        return numerator / denominator