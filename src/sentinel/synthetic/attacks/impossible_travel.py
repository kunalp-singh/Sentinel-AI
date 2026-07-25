from datetime import timedelta
from ipaddress import ip_address
from uuid import uuid4

from faker import Faker

from sentinel.domain import (
    DeviceFingerprint,
    EventOutcome,
    GeoLocation,
    SecurityEvent,
    ThreatLabel,
)
from sentinel.synthetic.attacks.base import AttackInjector
from sentinel.synthetic.personas import BehavioralPersona

_REMOTE_LOCATIONS = (
    GeoLocation(
        country_code="GB",
        city="London",
        latitude=51.5074,
        longitude=-0.1278,
    ),
    GeoLocation(
        country_code="US",
        city="New York",
        latitude=40.7128,
        longitude=-74.0060,
    ),
    GeoLocation(
        country_code="JP",
        city="Tokyo",
        latitude=35.6762,
        longitude=139.6503,
    ),
    GeoLocation(
        country_code="AU",
        city="Sydney",
        latitude=-33.8688,
        longitude=151.2093,
    ),
    GeoLocation(
        country_code="DE",
        city="Berlin",
        latitude=52.5200,
        longitude=13.4050,
    ),
)


class ImpossibleTravelInjector(AttackInjector):
    """Inject geographically impossible consecutive activity."""

    def __init__(
        self,
        seed: int = 42,
        travel_minutes: int = 30,
    ) -> None:
        super().__init__(seed)

        if travel_minutes <= 0:
            raise ValueError(
                "travel_minutes must be positive"
            )

        self._travel_minutes = travel_minutes

        Faker.seed(seed)
        self._faker = Faker()

    def inject(
        self,
        events: list[SecurityEvent],
        persona: BehavioralPersona,
    ) -> list[SecurityEvent]:
        if not events:
            raise ValueError(
                "cannot inject impossible travel into an empty event list"
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

        remote_location = self._choose_remote_location(
            persona
        )

        attack_event = SecurityEvent(
            event_id=f"EVENT_{uuid4().hex[:16]}",
            entity_id=persona.entity_id,
            entity_type=persona.entity_type,
            timestamp=anchor.timestamp
            + timedelta(
                minutes=self._travel_minutes
            ),
            source_ip=ip_address(
                self._faker.ipv4_public()
            ),
            geo_location=remote_location,
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
            device_fingerprint=DeviceFingerprint(
                fingerprint_id=(
                    "unknown_impossible_travel_device"
                ),
                operating_system="unknown",
                browser="unknown",
                device_type="unknown",
            ),
            label=ThreatLabel.IMPOSSIBLE_TRAVEL,
        )

        combined = [*events, attack_event]

        return sorted(
            combined,
            key=lambda event: event.timestamp,
        )

    def _choose_remote_location(
        self,
        persona: BehavioralPersona,
    ) -> GeoLocation:
        candidates = [
            location
            for location in _REMOTE_LOCATIONS
            if (
                location.country_code
                != persona.home_location.country_code
            )
        ]

        if not candidates:
            raise ValueError(
                "no remote location available"
            )

        return candidates[
            int(
                self._rng.integers(
                    0,
                    len(candidates),
                )
            )
        ]