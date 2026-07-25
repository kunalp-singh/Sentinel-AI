from datetime import timedelta
from ipaddress import ip_address
from uuid import uuid4

from faker import Faker

from sentinel.domain import (
    AuthMethod,
    DeviceFingerprint,
    EventOutcome,
    SecurityEvent,
    ThreatLabel,
)
from sentinel.synthetic.attacks.base import AttackInjector
from sentinel.synthetic.personas import BehavioralPersona


class BruteForceInjector(AttackInjector):
    """Inject a burst of failed authentication attempts."""

    def __init__(
        self,
        seed: int = 42,
        min_attempts: int = 5,
        max_attempts: int = 12,
    ) -> None:
        super().__init__(seed)

        if min_attempts < 2:
            raise ValueError("min_attempts must be at least 2")

        if max_attempts < min_attempts:
            raise ValueError(
                "max_attempts must be >= min_attempts"
            )

        self._min_attempts = min_attempts
        self._max_attempts = max_attempts

        Faker.seed(seed)
        self._faker = Faker()

    def inject(
        self,
        events: list[SecurityEvent],
        persona: BehavioralPersona,
    ) -> list[SecurityEvent]:
        if not events:
            raise ValueError(
                "cannot inject brute force into an empty event list"
            )

        persona_events = [
            event
            for event in events
            if event.entity_id == persona.entity_id
        ]

        if not persona_events:
            raise ValueError(
                "no events found for the supplied persona"
            )

        anchor = persona_events[
            int(
                self._rng.integers(
                    0,
                    len(persona_events),
                )
            )
        ]

        attempt_count = int(
            self._rng.integers(
                self._min_attempts,
                self._max_attempts + 1,
            )
        )

        attacker_ip = ip_address(
            self._faker.ipv4_public()
        )

        attack_events: list[SecurityEvent] = []

        for attempt in range(attempt_count):
            timestamp = anchor.timestamp + timedelta(
                seconds=attempt * 15
            )

            attack_events.append(
                SecurityEvent(
                    event_id=f"EVENT_{uuid4().hex[:16]}",
                    entity_id=persona.entity_id,
                    entity_type=persona.entity_type,
                    timestamp=timestamp,
                    source_ip=attacker_ip,
                    geo_location=persona.home_location,
                    resource_accessed="authentication-service",
                    auth_method=AuthMethod.PASSWORD,
                    outcome=EventOutcome.FAILURE,
                    session_duration_seconds=0,
                    command_sequence=[
                        "AUTHENTICATE"
                    ],
                    device_fingerprint=DeviceFingerprint(
                        fingerprint_id="unknown_bruteforce_device",
                        operating_system="unknown",
                        browser="unknown",
                        device_type="unknown",
                    ),
                    label=ThreatLabel.BRUTE_FORCE,
                )
            )

        combined = [*events, *attack_events]

        return sorted(
            combined,
            key=lambda event: event.timestamp,
        )