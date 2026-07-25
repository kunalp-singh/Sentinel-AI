from dataclasses import dataclass
from datetime import time

from sentinel.domain import AuthMethod, EntityType, GeoLocation


@dataclass(frozen=True, slots=True)
class BehavioralPersona:
    """Persistent normal behavioral characteristics for one entity."""

    entity_id: str
    entity_type: EntityType
    peer_group: str

    home_location: GeoLocation

    typical_login_time: time
    login_time_std_minutes: float

    typical_session_minutes: float
    session_std_minutes: float

    known_device_ids: tuple[str, ...]
    common_resources: tuple[str, ...]
    auth_methods: tuple[AuthMethod, ...]

    events_per_day_mean: float

    def __post_init__(self) -> None:
        if not self.entity_id:
            raise ValueError("entity_id cannot be empty")

        if self.login_time_std_minutes <= 0:
            raise ValueError(
                "login_time_std_minutes must be positive"
            )

        if self.typical_session_minutes <= 0:
            raise ValueError(
                "typical_session_minutes must be positive"
            )

        if self.session_std_minutes <= 0:
            raise ValueError(
                "session_std_minutes must be positive"
            )

        if self.events_per_day_mean <= 0:
            raise ValueError(
                "events_per_day_mean must be positive"
            )

        if not self.known_device_ids:
            raise ValueError(
                "persona must have at least one known device"
            )

        if not self.common_resources:
            raise ValueError(
                "persona must have at least one common resource"
            )

        if not self.auth_methods:
            raise ValueError(
                "persona must have at least one authentication method"
            )