from typing import Any

import pandas as pd

from sentinel.domain import EventOutcome, SecurityEvent


class EventFeatureExtractor:
    """Convert security events into deterministic event-level features."""

    def extract(self, event: SecurityEvent) -> dict[str, Any]:
        """Extract features from a single security event."""

        timestamp = event.timestamp

        return {
            "event_id": event.event_id,
            "entity_id": event.entity_id,
            "timestamp": timestamp,
            "hour_of_day": timestamp.hour,
            "day_of_week": timestamp.weekday(),
            "is_weekend": int(timestamp.weekday() >= 5),
            "auth_failed": int(
                event.outcome == EventOutcome.FAILURE
            ),
            "session_duration_seconds": (
                event.session_duration_seconds
            ),
            "command_count": len(event.command_sequence),
            "latitude": event.geo_location.latitude,
            "longitude": event.geo_location.longitude,
            "operating_system": (
                event.device_fingerprint.operating_system
            ),
            "browser": event.device_fingerprint.browser,
            "device_type": (
                event.device_fingerprint.device_type
            ),
            "resource_accessed": event.resource_accessed,
            "auth_method": event.auth_method.value,
            "source_ip": str(event.source_ip),
            "label": (
                event.label.value
                if event.label is not None
                else None
            ),
        }

    def transform(
        self,
        events: list[SecurityEvent],
    ) -> pd.DataFrame:
        """Convert a collection of events into a feature DataFrame."""

        rows = [
            self.extract(event)
            for event in events
        ]

        return pd.DataFrame(rows)