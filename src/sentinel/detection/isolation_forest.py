from dataclasses import dataclass
from typing import Any, cast

import numpy as np
import pandas as pd
from numpy.typing import NDArray
from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]

from sentinel.features import MODEL_FEATURES


@dataclass(frozen=True)
class AnomalyPrediction:
    """Prediction produced by the anomaly detector."""

    anomaly_score: float
    is_anomaly: bool


class IsolationForestDetector:
    """Isolation Forest based behavioral anomaly detector."""

    def __init__(
        self,
        *,
        contamination: float = 0.01,
        n_estimators: int = 200,
        random_state: int = 42,
    ) -> None:
        if not 0.0 < contamination <= 0.5:
            raise ValueError(
                "contamination must be between 0 and 0.5"
            )

        if n_estimators <= 0:
            raise ValueError(
                "n_estimators must be greater than zero"
            )

        self._model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )

        self._fitted = False

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    def fit(
        self,
        X: pd.DataFrame,
    ) -> None:
        """Train the detector on normal historical features."""

        self._validate_matrix(X)

        if X.empty:
            raise ValueError(
                "cannot train detector on empty feature matrix"
            )

        self._model.fit(X)

        self._fitted = True

    def anomaly_scores(
        self,
        X: pd.DataFrame,
    ) -> NDArray[np.float64]:
        """
        Return anomaly scores.

        Larger SentinelAI scores mean more anomalous behavior.
        """

        self._require_fitted()
        self._validate_matrix(X)

        raw_scores = cast(
            Any,
            self._model.decision_function(X),
        )

        return np.asarray(
            -raw_scores,
            dtype=np.float64,
        )

    def predict(
        self,
        X: pd.DataFrame,
    ) -> list[AnomalyPrediction]:
        """Predict anomalies for a feature matrix."""

        self._require_fitted()
        self._validate_matrix(X)

        scores = self.anomaly_scores(X)

        raw_predictions = np.asarray(
            self._model.predict(X),
            dtype=np.int64,
        )

        return [
            AnomalyPrediction(
                anomaly_score=float(score),

                # Explicit conversion prevents np.bool_
                # from escaping our domain boundary.
                is_anomaly=bool(prediction == -1),
            )
            for score, prediction in zip(
                scores,
                raw_predictions,
                strict=True,
            )
        ]

    def _require_fitted(self) -> None:
        if not self._fitted:
            raise RuntimeError(
                "detector must be fitted before prediction"
            )

    @staticmethod
    def _validate_matrix(
        X: pd.DataFrame,
    ) -> None:
        expected = list(MODEL_FEATURES)
        actual = list(X.columns)

        if actual != expected:
            raise ValueError(
                "feature matrix columns do not match "
                "MODEL_FEATURES"
            )

        if X.isna().any().any():
            raise ValueError(
                "feature matrix contains missing values"
            )

        if not all(
            np.issubdtype(dtype, np.number)
            for dtype in X.dtypes
        ):
            raise ValueError(
                "feature matrix must contain only "
                "numeric values"
            )