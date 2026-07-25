from datetime import date, timedelta

import pandas as pd

from sentinel.domain import SecurityEvent
from sentinel.synthetic.generator import NormalEventGenerator
from sentinel.synthetic.personas import BehavioralPersona


class SyntheticDatasetBuilder:
    """Build tabular datasets from behavioral personas."""

    def __init__(
        self,
        generator: NormalEventGenerator,
    ) -> None:
        self._generator = generator

    def generate_normal_dataset(
        self,
        personas: list[BehavioralPersona],
        start_date: date,
        days: int,
    ) -> list[SecurityEvent]:
        if days <= 0:
            raise ValueError("days must be positive")

        events: list[SecurityEvent] = []

        for offset in range(days):
            current_date = start_date + timedelta(
                days=offset
            )

            for persona in personas:
                events.extend(
                    self._generator.generate_for_day(
                        persona,
                        current_date,
                    )
                )

        return sorted(
            events,
            key=lambda event: event.timestamp,
        )

    @staticmethod
    def to_dataframe(
        events: list[SecurityEvent],
    ) -> pd.DataFrame:
        rows = [
            event.model_dump(mode="json")
            for event in events
        ]

        return pd.DataFrame(rows)