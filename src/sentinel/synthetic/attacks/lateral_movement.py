from datetime import timedelta
from uuid import uuid4

from sentinel.domain import (
    DeviceFingerprint,
    EventOutcome,
    SecurityEvent,
    ThreatLabel,
)
from sentinel.synthetic.attacks.base import AttackInjector
from sentinel.synthetic.personas import BehavioralPersona

_LATERAL_RESOURCES = (
    "admin-console",
    "identity-service",
    "internal-database",
    "secrets-vault",
)


class LateralMovementInjector(AttackInjector):
    """Inject rapid traversal across unusual internal resources."""

    def __init__(
        self,
        seed: int = 42,
        interval_minutes: int = 3,
    ) -> None:
        super().__init__(seed)

        if interval_minutes <= 0:
            raise ValueError(
                "interval_minutes must be positive"
            )

        self._interval_minutes = interval_minutes

    def inject(
        self,
        events: list[SecurityEvent],
        persona: BehavioralPersona,
    ) -> list[SecurityEvent]:
        if not events:
            raise ValueError(
                "cannot inject lateral movement "
                "into an empty event list"
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

        attack_resources = tuple(
            resource
            for resource in _LATERAL_RESOURCES
            if resource not in persona.common_resources
        )

        if not attack_resources:
            raise ValueError(
                "no novel resources available "
                "for lateral movement"
            )

        attack_events: list[SecurityEvent] = []

        for index, resource in enumerate(
            attack_resources,
            start=1,
        ):
            attack_events.append(
                SecurityEvent(
                    event_id=f"EVENT_{uuid4().hex[:16]}",
                    entity_id=persona.entity_id,
                    entity_type=persona.entity_type,
                    timestamp=(
                        anchor.timestamp
                        + timedelta(
                            minutes=(
                                index
                                * self._interval_minutes
                            )
                        )
                    ),
                    source_ip=anchor.source_ip,
                    geo_location=anchor.geo_location,
                    resource_accessed=resource,
                    auth_method=anchor.auth_method,
                    outcome=EventOutcome.SUCCESS,
                    session_duration_seconds=60,
                    command_sequence=[
                        f"AUTHENTICATE {resource}",
                        f"ENUMERATE {resource}",
                        f"ACCESS {resource}",
                    ],
                    device_fingerprint=DeviceFingerprint(
                        fingerprint_id=(
                            anchor.device_fingerprint
                            .fingerprint_id
                        ),
                        operating_system=(
                            anchor.device_fingerprint
                            .operating_system
                        ),
                        browser=(
                            anchor.device_fingerprint.browser
                        ),
                        device_type=(
                            anchor.device_fingerprint
                            .device_type
                        ),
                    ),
                    label=ThreatLabel.LATERAL_MOVEMENT,
                )
            )

        combined = [
            *events,
            *attack_events,
        ]

        return sorted(
            combined,
            key=lambda event: event.timestamp,
        )