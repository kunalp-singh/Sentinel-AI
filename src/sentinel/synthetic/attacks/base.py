from abc import ABC, abstractmethod

import numpy as np

from sentinel.domain import SecurityEvent
from sentinel.synthetic.personas import BehavioralPersona


class AttackInjector(ABC):
    """Interface implemented by synthetic attack injectors."""

    def __init__(self, seed: int = 42) -> None:
        self._rng = np.random.default_rng(seed)

    @abstractmethod
    def inject(
        self,
        events: list[SecurityEvent],
        persona: BehavioralPersona,
    ) -> list[SecurityEvent]:
        """Return events with a synthetic attack sequence injected."""