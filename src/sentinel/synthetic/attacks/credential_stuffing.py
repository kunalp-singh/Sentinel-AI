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
from sentinel.synthetic.attacks.campaign import CampaignInjector
from sentinel.synthetic.personas import BehavioralPersona


class CredentialStuffingInjector(CampaignInjector):
    """Inject authentication attempts across multiple user accounts."""

    def __init__(
        self,
        seed: int = 42,
        min_targets: int = 5,
        max_targets: int = 12,
        success_rate: float = 0.1,
    ) -> None:
        super().__init__(seed)

        if min_targets < 2:
            raise ValueError(
                "min_targets must be at least 2"
            )

        if max_targets < min_targets:
            raise ValueError(
                "max_targets must be >= min_targets"
            )

        if not 0.0 <= success_rate <= 1.0:
            raise ValueError(
                "success_rate must be between 0 and 1"
            )

        self._min_targets = min_targets
        self._max_targets = max_targets
        self._success_rate = success_rate

        Faker.seed(seed)
        self._faker = Faker()

    def inject(
        self,
        events: list[SecurityEvent],
        personas: list[BehavioralPersona],
    ) -> list[SecurityEvent]:
        if not events:
            raise ValueError(
                "cannot inject credential stuffing "
                "into an empty event list"
            )

        if len(personas) < self._min_targets:
            raise ValueError(
                "not enough personas for credential stuffing"
            )

        target_count = min(
            int(
                self._rng.integers(
                    self._min_targets,
                    self._max_targets + 1,
                )
            ),
            len(personas),
        )

        target_indices = self._rng.choice(
            len(personas),
            size=target_count,
            replace=False,
        )

        targets = [
            personas[int(index)]
            for index in target_indices
        ]

        anchor_timestamp = min(
            event.timestamp
            for event in events
        )

        campaign_offset_minutes = int(
            self._rng.integers(30, 180)
        )

        campaign_start = (
            anchor_timestamp
            + timedelta(
                minutes=campaign_offset_minutes
            )
        )

        attacker_ip = ip_address(
            self._faker.ipv4_public()
        )

        attacker_device = DeviceFingerprint(
            fingerprint_id="credential_stuffing_device",
            operating_system="unknown",
            browser="automated-client",
            device_type="unknown",
        )

        attack_events: list[SecurityEvent] = []

        for index, persona in enumerate(targets):
            successful = (
                self._rng.random()
                < self._success_rate
            )

            attack_events.append(
                SecurityEvent(
                    event_id=f"EVENT_{uuid4().hex[:16]}",
                    entity_id=persona.entity_id,
                    entity_type=persona.entity_type,
                    timestamp=(
                        campaign_start
                        + timedelta(
                            seconds=index * 10
                        )
                    ),
                    source_ip=attacker_ip,
                    geo_location=persona.home_location,
                    resource_accessed=(
                        "authentication-service"
                    ),
                    auth_method=AuthMethod.PASSWORD,
                    outcome=(
                        EventOutcome.SUCCESS
                        if successful
                        else EventOutcome.FAILURE
                    ),
                    session_duration_seconds=(
                        30 if successful else 0
                    ),
                    command_sequence=[
                        "AUTHENTICATE"
                    ],
                    device_fingerprint=attacker_device,
                    label=(
                        ThreatLabel.CREDENTIAL_STUFFING
                    ),
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