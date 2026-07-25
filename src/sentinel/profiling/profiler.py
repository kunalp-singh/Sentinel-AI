from collections import defaultdict

import numpy as np

from sentinel.domain import EventOutcome, SecurityEvent, ThreatLabel
from sentinel.profiling.profile import (
    DeviceProfile,
    EntityBehaviorProfile,
)


class EntityProfiler:
    """Learn per-entity behavioral baselines from historical events."""

    def build(
        self,
        events: list[SecurityEvent],
    ) -> dict[str, EntityBehaviorProfile]:
        if not events:
            raise ValueError(
                "cannot build profiles from an empty event list"
            )

        normal_events = [
            event
            for event in events
            if (
                event.label is None
                or event.label == ThreatLabel.NORMAL
            )
        ]

        if not normal_events:
            raise ValueError(
                "no normal events available for profiling"
            )

        grouped: dict[str, list[SecurityEvent]] = defaultdict(list)

        for event in normal_events:
            grouped[event.entity_id].append(event)

        return {
            entity_id: self._build_entity_profile(entity_events)
            for entity_id, entity_events in grouped.items()
        }

    def _build_entity_profile(
        self,
        events: list[SecurityEvent],
    ) -> EntityBehaviorProfile:
        entity_id = events[0].entity_id

        hours = np.asarray(
            [
                event.timestamp.hour
                + event.timestamp.minute / 60.0
                for event in events
            ],
            dtype=float,
        )

        durations = np.asarray(
            [
                event.session_duration_seconds
                for event in events
            ],
            dtype=float,
        )

        failure_count = sum(
            event.outcome == EventOutcome.FAILURE
            for event in events
        )

        devices = {
            (
                event.device_fingerprint.fingerprint_id,
                event.device_fingerprint.operating_system,
                event.device_fingerprint.browser,
                event.device_fingerprint.device_type,
            )
            for event in events
        }

        return EntityBehaviorProfile(
            entity_id=entity_id,
            event_count=len(events),
            mean_hour=float(np.mean(hours)),
            hour_std=float(np.std(hours)),
            mean_session_duration=float(np.mean(durations)),
            session_duration_std=float(np.std(durations)),
            authentication_failure_rate=(
                failure_count / len(events)
            ),
            known_source_ips=frozenset(
                str(event.source_ip)
                for event in events
            ),
            known_resources=frozenset(
                event.resource_accessed
                for event in events
            ),
            known_auth_methods=frozenset(
                event.auth_method.value
                for event in events
            ),
            known_devices=tuple(
                DeviceProfile(
                    fingerprint_id=fingerprint_id,
                    operating_system=operating_system,
                    browser=browser,
                    device_type=device_type,
                )
                for (
                    fingerprint_id,
                    operating_system,
                    browser,
                    device_type,
                ) in sorted(devices)
            ),
        )