from math import asin, cos, radians, sin, sqrt

from sentinel.domain import GeoLocation

_EARTH_RADIUS_KM = 6371.0


def haversine_distance_km(
    first: GeoLocation,
    second: GeoLocation,
) -> float:
    """Calculate great-circle distance between two locations."""

    latitude_delta = radians(
        second.latitude - first.latitude
    )
    longitude_delta = radians(
        second.longitude - first.longitude
    )

    first_latitude = radians(first.latitude)
    second_latitude = radians(second.latitude)

    value = (
        sin(latitude_delta / 2) ** 2
        + cos(first_latitude)
        * cos(second_latitude)
        * sin(longitude_delta / 2) ** 2
    )

    return (
        2
        * _EARTH_RADIUS_KM
        * asin(sqrt(value))
    )


def implied_speed_kmh(
    first_location: GeoLocation,
    second_location: GeoLocation,
    elapsed_seconds: float,
) -> float:
    """Calculate implied travel velocity between two events."""

    if elapsed_seconds <= 0:
        raise ValueError(
            "elapsed_seconds must be positive"
        )

    distance = haversine_distance_km(
        first_location,
        second_location,
    )

    elapsed_hours = elapsed_seconds / 3600

    return distance / elapsed_hours