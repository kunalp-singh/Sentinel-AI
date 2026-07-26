from dataclasses import dataclass
from datetime import date, timedelta

from sentinel.classification import (
    AnomalyTypeClassifier,
    ClassificationResult,
)
from sentinel.detection import (
    HybridRiskScorer,
    IsolationForestDetector,
)
from sentinel.domain import SecurityEvent
from sentinel.explainability import (
    SecurityExplainer,
    SecurityExplanation,
)
from sentinel.features import (
    MODEL_FEATURES,
    FeatureMatrixBuilder,
)
from sentinel.profiling import (
    EntityBehaviorProfile,
    EntityProfiler,
)
from sentinel.synthetic import (
    NormalEventGenerator,
    PersonaFactory,
)


@dataclass(frozen=True)
class AnalysisResult:
    """Complete SentinelAI event assessment."""

    explanation: SecurityExplanation
    classification: ClassificationResult

class SentinelAnalysisService:
    """In-memory SentinelAI detection pipeline."""

    def __init__(
        self,
        seed: int = 42,
        user_count: int = 20,
    ) -> None:
        self._seed = seed
        self._user_count = user_count

        self._builder = FeatureMatrixBuilder()
        self._risk_scorer = HybridRiskScorer()
        self._explainer = SecurityExplainer()

        self._detector = IsolationForestDetector(
            contamination=0.01,
            n_estimators=200,
            random_state=seed,
        )

        self._classifier = AnomalyTypeClassifier()

        self._profiles: dict[
            str,
            EntityBehaviorProfile,
        ] = {}

        self._history: list[SecurityEvent] = []

        self._initialize()

    @property
    def profiles(
        self,
    ) -> dict[str, EntityBehaviorProfile]:
        return self._profiles

    @property
    def history(self) -> list[SecurityEvent]:
        return self._history

    def _initialize(self) -> None:
        """Build demo profiles and train the anomaly detector."""

        personas = PersonaFactory(
            seed=self._seed,
        ).create_users(
            self._user_count,
        )

        generator = NormalEventGenerator(
            seed=self._seed,
        )

        profile_history: list[SecurityEvent] = []
        training_events: list[SecurityEvent] = []

        start = date(2026, 7, 1)

        for persona in personas:
            for offset in range(7):
                profile_history.extend(
                    generator.generate_for_day(
                        persona,
                        start + timedelta(
                            days=offset,
                        ),
                    )
                )

            for offset in range(7, 14):
                training_events.extend(
                    generator.generate_for_day(
                        persona,
                        start + timedelta(
                            days=offset,
                        ),
                    )
                )

        self._profiles = EntityProfiler().build(
            profile_history
        )

        training_matrix = self._builder.build(
            training_events,
            self._profiles,
        )

        self._detector.fit(
            training_matrix.X
        )

        # Sequential extraction needs prior activity.
        self._history = sorted(
            profile_history + training_events,
            key=lambda event: event.timestamp,
        )

    def analyze(
        self,
        event: SecurityEvent,
    ) -> AnalysisResult:
        """Analyze one security event."""

        if event.entity_id not in self._profiles:
            raise ValueError(
                f"unknown entity: {event.entity_id}"
            )

        context = [
            *self._history,
            event,
        ]

        matrix = self._builder.build(
            context,
            self._profiles,
        )

        # Event may not be the final row because the
        # feature builder sorts events by timestamp.
        matching_positions = [
            position
            for position, event_id in enumerate(
                matrix.metadata["event_id"]
            )
            if str(event_id) == str(event.event_id)
        ]

        if not matching_positions:
            raise ValueError(
                f"event not found in feature matrix: "
                f"{event.event_id}"
            )

        event_index = matching_positions[0]

        event_features = matrix.X.iloc[
            [event_index]
        ]

        predictions = self._detector.predict(
            event_features
        )

        prediction = predictions[0]

        features = {
            feature: float(
                matrix.X.iloc[event_index][
                    feature
                ]
            )
            for feature in MODEL_FEATURES
        }

        assessment = self._risk_scorer.assess(
            features,
            prediction,
        )

        explanation = self._explainer.explain(
            event,
            assessment,
            prediction,
        )

        classification = self._classifier.classify(
            features,
            is_suspicious=(
                assessment.score >= 30.0
            ),
        )

        return AnalysisResult(
            explanation=explanation,
            classification=classification,
        )