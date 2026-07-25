from dataclasses import dataclass

import pandas as pd

from sentinel.domain import SecurityEvent
from sentinel.features.deviation_features import (
    ProfileDeviationExtractor,
)
from sentinel.features.event_features import EventFeatureExtractor
from sentinel.features.sequential_features import (
    SequentialFeatureExtractor,
)
from sentinel.profiling import EntityBehaviorProfile

MODEL_FEATURES = (
    "hour_of_day",
    "day_of_week",
    "is_weekend",
    "auth_failed",
    "session_duration_seconds",
    "command_count",
    "latitude",
    "longitude",
    "is_new_ip",
    "is_new_resource",
    "is_new_device",
    "device_fingerprint_mismatch",
    "hour_deviation",
    "hour_deviation_zscore",
    "session_duration_deviation",
    "session_duration_deviation_zscore",
    "events_10m",
    "failed_logins_10m",
    "unique_resources_30m",
    "resource_access_velocity_30m",
    "source_ip_entity_fanout_10m",
    "distance_from_previous_km",
    "implied_speed_kmh",
)


@dataclass(frozen=True)
class FeatureMatrix:
    """Model-ready features separated from labels and metadata."""

    X: pd.DataFrame
    y: pd.Series
    metadata: pd.DataFrame


class FeatureMatrixBuilder:
    """Combine SentinelAI feature extractors into a numeric matrix."""

    def __init__(self) -> None:
        self._event_extractor = EventFeatureExtractor()
        self._deviation_extractor = ProfileDeviationExtractor()
        self._sequential_extractor = SequentialFeatureExtractor()

    @staticmethod
    def _standardized_deviations(
        deviation_features: dict[str, float | int],
        profile: EntityBehaviorProfile,
    ) -> dict[str, float]:
        """Calculate standardized behavioral deviations."""

        hour_std = profile.hour_std
        session_std = profile.session_duration_std

        hour_zscore = (
            float(deviation_features["hour_deviation"]) / hour_std
            if hour_std > 0
            else 0.0
        )

        session_zscore = (
            float(
                deviation_features[
                    "session_duration_deviation"
                ]
            )
            / session_std
            if session_std > 0
            else 0.0
        )

        return {
            "hour_deviation_zscore": hour_zscore,
            "session_duration_deviation_zscore": session_zscore,
        }

    def build(
        self,
        events: list[SecurityEvent],
        profiles: dict[str, EntityBehaviorProfile],
    ) -> FeatureMatrix:
        """Build a model-ready feature matrix."""

        if not events:
            raise ValueError(
                "cannot build feature matrix from empty events"
            )

        rows: list[dict[str, float | int]] = []
        labels: list[str | None] = []
        metadata: list[dict[str, object]] = []

        ordered_events = sorted(
            events,
            key=lambda event: event.timestamp,
        )

        for event in ordered_events:
            profile = profiles.get(event.entity_id)

            if profile is None:
                raise ValueError(
                    f"missing behavioral profile for "
                    f"{event.entity_id}"
                )

            event_features = self._event_extractor.extract(
                event
            )

            deviation_features = (
                self._deviation_extractor.extract(
                    event,
                    profile,
                )
            )

            standardized_features = (
                self._standardized_deviations(
                    deviation_features,
                    profile,
                )
            )

            sequential_features = (
                self._sequential_extractor.extract(
                    event,
                    ordered_events,
                )
            )

            combined = {
                **event_features,
                **deviation_features,
                **standardized_features,
                **sequential_features,
            }

            rows.append(
                {
                    feature: combined[feature]
                    for feature in MODEL_FEATURES
                }
            )

            labels.append(
                event.label.value
                if event.label is not None
                else None
            )

            metadata.append(
                {
                    "event_id": event.event_id,
                    "entity_id": event.entity_id,
                    "timestamp": event.timestamp,
                }
            )

        X = pd.DataFrame(
            rows,
            columns=MODEL_FEATURES,
        ).astype(float)

        y = pd.Series(
            labels,
            name="label",
            dtype="object",
        )

        metadata_frame = pd.DataFrame(metadata)

        return FeatureMatrix(
            X=X,
            y=y,
            metadata=metadata_frame,
        )