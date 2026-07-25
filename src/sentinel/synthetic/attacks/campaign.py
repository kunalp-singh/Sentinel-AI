from abc import ABC, abstractmethod

import numpy as np

from sentinel.domain import SecurityEvent
from sentinel.synthetic.personas import BehavioralPersona


class CampaignInjector(ABC):
    """Base class for attacks spanning multiple entities."""

    def __init__(self, seed: int = 42) -> None:
        self._rng = np.random.default_rng(seed)

    @abstractmethod
    def inject(
        self,
        events: list[SecurityEvent],
        personas: list[BehavioralPersona],
    ) -> list[SecurityEvent]:
        """Inject a multi-entity attack campaign."""