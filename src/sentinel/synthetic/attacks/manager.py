from dataclasses import dataclass

import numpy as np

from sentinel.domain import SecurityEvent, ThreatLabel
from sentinel.synthetic.attacks.base import AttackInjector
from sentinel.synthetic.personas import BehavioralPersona


@dataclass(frozen=True, slots=True)
class AttackInjectionResult:
    """Summary of controlled synthetic attack injection."""

    events: list[SecurityEvent]
    original_event_count: int
    injected_event_count: int
    attacked_entity_count: int

    @property
    def total_event_count(self) -> int:
        return len(self.events)

    @property
    def anomaly_rate(self) -> float:
        if not self.events:
            return 0.0

        malicious_count = sum(
            event.label != ThreatLabel.NORMAL
            for event in self.events
        )

        return malicious_count / len(self.events)


class AttackRateManager:
    """Inject attacks while respecting a target event-level anomaly rate."""

    def __init__(self, seed: int = 42) -> None:
        self._rng = np.random.default_rng(seed)

    def inject(
        self,
        events: list[SecurityEvent],
        personas: list[BehavioralPersona],
        injector: AttackInjector,
        target_rate: float,
    ) -> AttackInjectionResult:
        if not 0.005 <= target_rate <= 0.03:
            raise ValueError(
                "target_rate must be between 0.005 and 0.03"
            )

        if not events:
            raise ValueError("events cannot be empty")

        if not personas:
            raise ValueError("personas cannot be empty")

        existing_malicious = sum(
            event.label != ThreatLabel.NORMAL
            for event in events
        )

        if existing_malicious:
            raise ValueError(
                "AttackRateManager expects a normal baseline dataset"
            )

        target_malicious_count = self._calculate_target_count(
            len(events),
            target_rate,
        )

        shuffled_personas = list(personas)
        self._rng.shuffle(shuffled_personas)

        current_events = list(events)
        injected_count = 0
        attacked_entities = 0

        for persona in shuffled_personas:
            if injected_count >= target_malicious_count:
                break

            before_count = len(current_events)

            candidate_events = injector.inject(
                current_events,
                persona,
            )

            added_count = len(candidate_events) - before_count

            if added_count <= 0:
                continue

            projected_injected = injected_count + added_count
            projected_total = len(events) + projected_injected

            projected_rate = (
                projected_injected / projected_total
            )

            current_rate = (
                injected_count
                / (len(events) + injected_count)
            )

            if (
                abs(projected_rate - target_rate)
                > abs(current_rate - target_rate)
                and injected_count > 0
            ):
                break

            current_events = candidate_events
            injected_count = projected_injected
            attacked_entities += 1

        current_events.sort(
            key=lambda event: event.timestamp
        )

        return AttackInjectionResult(
            events=current_events,
            original_event_count=len(events),
            injected_event_count=injected_count,
            attacked_entity_count=attacked_entities,
        )

    @staticmethod
    def _calculate_target_count(
        normal_count: int,
        target_rate: float,
    ) -> int:
        """
        Calculate malicious events required when the rate is measured
        against the final dataset.

        malicious / (normal + malicious) = target_rate
        """

        required = (
            target_rate * normal_count
            / (1.0 - target_rate)
        )

        return max(1, round(required))