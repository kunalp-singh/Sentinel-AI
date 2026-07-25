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

_SPOOFED_FINGERPRINTS = (
    ("Windows 11", "Chrome", "desktop"),
    ("Linux", "Chromium", "desktop"),
    ("Android", "Chrome Mobile", "mobile"),
)


class DeviceSpoofingInjector(AttackInjector):
    """Reuse a known device ID with a mismatched fingerprint."""

    def __init__(
        self,
        seed: int = 42,
        delay_minutes: int = 5,
    ) -> None:
        super().__init__(seed)

        if delay_minutes <= 0:
            raise ValueError(
                "delay_minutes must be positive"
            )

        self._delay_minutes = delay_minutes

    def inject(
        self,
        events: list[SecurityEvent],
        persona: BehavioralPersona,
    ) -> list[SecurityEvent]:
        if not events:
            raise ValueError(
                "cannot inject device spoofing "
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

        original_device = anchor.device_fingerprint

        candidates = [
            fingerprint
            for fingerprint in _SPOOFED_FINGERPRINTS
            if (
                fingerprint[0]
                != original_device.operating_system
                or fingerprint[1]
                != original_device.browser
                or fingerprint[2]
                != original_device.device_type
            )
        ]

        if not candidates:
            raise ValueError(
                "no mismatched device fingerprint available"
            )

        spoofed_os, spoofed_browser, spoofed_type = (
            candidates[
                int(
                    self._rng.integers(
                        0,
                        len(candidates),
                    )
                )
            ]
        )

        spoofed_device = DeviceFingerprint(
            fingerprint_id=original_device.fingerprint_id,
            operating_system=spoofed_os,
            browser=spoofed_browser,
            device_type=spoofed_type,
        )

        attack_event = SecurityEvent(
            event_id=f"EVENT_{uuid4().hex[:16]}",
            entity_id=persona.entity_id,
            entity_type=persona.entity_type,
            timestamp=(
                anchor.timestamp
                + timedelta(
                    minutes=self._delay_minutes
                )
            ),
            source_ip=anchor.source_ip,
            geo_location=anchor.geo_location,
            resource_accessed=anchor.resource_accessed,
            auth_method=anchor.auth_method,
            outcome=EventOutcome.SUCCESS,
            session_duration_seconds=(
                anchor.session_duration_seconds
            ),
            command_sequence=[
                "AUTHENTICATE",
                f"ACCESS {anchor.resource_accessed}",
            ],
            device_fingerprint=spoofed_device,
            label=ThreatLabel.DEVICE_SPOOFING,
        )

        combined = [
            *events,
            attack_event,
        ]

        return sorted(
            combined,
            key=lambda event: event.timestamp,
        )