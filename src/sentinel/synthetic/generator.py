from datetime import UTC, date, datetime, timedelta
from ipaddress import ip_address
from uuid import uuid4

import numpy as np
from faker import Faker

from sentinel.domain import (
    DeviceFingerprint,
    EventOutcome,
    SecurityEvent,
    ThreatLabel,
)
from sentinel.synthetic.personas import BehavioralPersona


class NormalEventGenerator:
    """Generate normal events around persistent entity baselines."""

    def __init__(self, seed: int = 42) -> None:
        self._rng = np.random.default_rng(seed)

        Faker.seed(seed)
        self._faker = Faker()

    def generate_for_day(
        self,
        persona: BehavioralPersona,
        event_date: date,
    ) -> list[SecurityEvent]:
        event_count = max(
            1,
            int(
                self._rng.poisson(
                    persona.events_per_day_mean
                )
            ),
        )

        events = [
            self._generate_event(
                persona,
                event_date,
            )
            for _ in range(event_count)
        ]

        return sorted(
            events,
            key=lambda event: event.timestamp,
        )

    def _generate_event(
        self,
        persona: BehavioralPersona,
        event_date: date,
    ) -> SecurityEvent:
        timestamp = self._generate_timestamp(
            persona,
            event_date,
        )

        session_minutes = max(
            1.0,
            float(
                self._rng.normal(
                    persona.typical_session_minutes,
                    persona.session_std_minutes,
                )
            ),
        )

        resource = str(
            self._rng.choice(
                persona.common_resources
            )
        )

        auth_method = self._rng.choice(
            persona.auth_methods
        )

        device_id = str(
            self._rng.choice(
                persona.known_device_ids
            )
        )

        return SecurityEvent(
            event_id=f"EVENT_{uuid4().hex[:16]}",
            entity_id=persona.entity_id,
            entity_type=persona.entity_type,
            timestamp=timestamp,
            source_ip=ip_address(self._faker.ipv4_public()),
            geo_location=persona.home_location,
            resource_accessed=resource,
            auth_method=auth_method,
            outcome=EventOutcome.SUCCESS,
            session_duration_seconds=int(
                session_minutes * 60
            ),
            command_sequence=self._normal_commands(
                resource
            ),
            device_fingerprint=DeviceFingerprint(
                fingerprint_id=device_id,
                operating_system="macOS",
                browser="Firefox",
                device_type="laptop",
            ),
            label=ThreatLabel.NORMAL,
        )

    def _generate_timestamp(
        self,
        persona: BehavioralPersona,
        event_date: date,
    ) -> datetime:
        baseline_minutes = (
            persona.typical_login_time.hour * 60
            + persona.typical_login_time.minute
        )

        sampled_minutes = int(
            self._rng.normal(
                baseline_minutes,
                persona.login_time_std_minutes,
            )
        )

        sampled_minutes = int(
            np.clip(
                sampled_minutes,
                0,
                (24 * 60) - 1,
            )
        )

        timestamp = datetime(
            event_date.year,
            event_date.month,
            event_date.day,
            tzinfo=UTC,
        )

        return timestamp + timedelta(
            minutes=sampled_minutes
        )

    def _normal_commands(
        self,
        resource: str,
    ) -> list[str]:
        return [
            f"ACCESS {resource}",
            f"READ {resource}",
        ]