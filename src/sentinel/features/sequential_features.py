from datetime import timedelta
from math import asin, cos, radians, sin, sqrt

from sentinel.domain import EventOutcome, SecurityEvent


class SequentialFeatureExtractor:
    """Extract temporal and window-based behavioral features."""

    def extract(
        self,
        event: SecurityEvent,
        events: list[SecurityEvent],
    ) -> dict[str, float | int]:
        history = [
            candidate
            for candidate in events
            if candidate.timestamp <= event.timestamp
        ]

        return {
            "events_10m": self._events_in_window(
                event,
                history,
                minutes=10,
            ),
            "failed_logins_10m": self._failed_logins(
                event,
                history,
                minutes=10,
            ),
            "unique_resources_30m": self._unique_resources(
                event,
                history,
                minutes=30,
            ),
            "resource_access_velocity_30m": (
                self._resource_access_velocity(
                    event,
                    history,
                    minutes=30,
                )
            ),
            "source_ip_entity_fanout_10m": (
                self._source_ip_entity_fanout(
                    event,
                    history,
                    minutes=10,
                )
            ),
            **self._travel_features(
                event,
                history,
            ),
        }

    @staticmethod
    def _window(
        event: SecurityEvent,
        events: list[SecurityEvent],
        minutes: int,
    ) -> list[SecurityEvent]:
        start = event.timestamp - timedelta(
            minutes=minutes
        )

        return [
            candidate
            for candidate in events
            if (
                start <= candidate.timestamp
                <= event.timestamp
            )
        ]

    def _events_in_window(
        self,
        event: SecurityEvent,
        events: list[SecurityEvent],
        minutes: int,
    ) -> int:
        window = self._window(
            event,
            events,
            minutes,
        )

        return sum(
            candidate.entity_id == event.entity_id
            for candidate in window
        )

    def _failed_logins(
        self,
        event: SecurityEvent,
        events: list[SecurityEvent],
        minutes: int,
    ) -> int:
        window = self._window(
            event,
            events,
            minutes,
        )

        return sum(
            candidate.entity_id == event.entity_id
            and candidate.outcome == EventOutcome.FAILURE
            for candidate in window
        )

    def _unique_resources(
        self,
        event: SecurityEvent,
        events: list[SecurityEvent],
        minutes: int,
    ) -> int:
        window = self._window(
            event,
            events,
            minutes,
        )

        resources = {
            candidate.resource_accessed
            for candidate in window
            if candidate.entity_id == event.entity_id
        }

        return len(resources)

    def _resource_access_velocity(
        self,
        event: SecurityEvent,
        events: list[SecurityEvent],
        minutes: int,
    ) -> float:
        unique_resources = self._unique_resources(
            event,
            events,
            minutes,
        )

        return unique_resources / minutes

    def _source_ip_entity_fanout(
        self,
        event: SecurityEvent,
        events: list[SecurityEvent],
        minutes: int,
    ) -> int:
        window = self._window(
            event,
            events,
            minutes,
        )

        entities = {
            candidate.entity_id
            for candidate in window
            if candidate.source_ip == event.source_ip
        }

        return len(entities)

    def _travel_features(
        self,
        event: SecurityEvent,
        events: list[SecurityEvent],
    ) -> dict[str, float]:
        previous = self._previous_entity_event(
            event,
            events,
        )

        if previous is None:
            return {
                "distance_from_previous_km": 0.0,
                "implied_speed_kmh": 0.0,
            }

        distance = self._haversine_km(
            previous.geo_location.latitude,
            previous.geo_location.longitude,
            event.geo_location.latitude,
            event.geo_location.longitude,
        )

        elapsed_hours = (
            event.timestamp - previous.timestamp
        ).total_seconds() / 3600.0

        if elapsed_hours <= 0:
            speed = 0.0
        else:
            speed = distance / elapsed_hours

        return {
            "distance_from_previous_km": distance,
            "implied_speed_kmh": speed,
        }

    @staticmethod
    def _previous_entity_event(
        event: SecurityEvent,
        events: list[SecurityEvent],
    ) -> SecurityEvent | None:
        previous = [
            candidate
            for candidate in events
            if (
                candidate.entity_id == event.entity_id
                and candidate.event_id != event.event_id
                and candidate.timestamp < event.timestamp
            )
        ]

        if not previous:
            return None

        return max(
            previous,
            key=lambda candidate: candidate.timestamp,
        )

    @staticmethod
    def _haversine_km(
        latitude_1: float,
        longitude_1: float,
        latitude_2: float,
        longitude_2: float,
    ) -> float:
        earth_radius_km = 6371.0

        lat_1 = radians(latitude_1)
        lon_1 = radians(longitude_1)
        lat_2 = radians(latitude_2)
        lon_2 = radians(longitude_2)

        delta_lat = lat_2 - lat_1
        delta_lon = lon_2 - lon_1

        value = (
            sin(delta_lat / 2.0) ** 2
            + cos(lat_1)
            * cos(lat_2)
            * sin(delta_lon / 2.0) ** 2
        )

        return (
            2.0
            * earth_radius_km
            * asin(sqrt(value))
        )