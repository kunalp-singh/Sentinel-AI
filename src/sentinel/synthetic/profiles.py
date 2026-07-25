from datetime import time

import numpy as np
from faker import Faker

from sentinel.domain import AuthMethod, EntityType, GeoLocation
from sentinel.synthetic.personas import BehavioralPersona

_LOCATIONS = (
    GeoLocation(
        country_code="IN",
        city="Bengaluru",
        latitude=12.9716,
        longitude=77.5946,
    ),
    GeoLocation(
        country_code="IN",
        city="Mumbai",
        latitude=19.0760,
        longitude=72.8777,
    ),
    GeoLocation(
        country_code="IN",
        city="Delhi",
        latitude=28.6139,
        longitude=77.2090,
    ),
    GeoLocation(
        country_code="IN",
        city="Hyderabad",
        latitude=17.3850,
        longitude=78.4867,
    ),
    GeoLocation(
        country_code="IN",
        city="Pune",
        latitude=18.5204,
        longitude=73.8567,
    ),
)


_PEER_RESOURCES: dict[str, tuple[str, ...]] = {
    "engineering": (
        "gitlab",
        "jira",
        "internal-api",
        "artifact-registry",
        "dev-database",
    ),
    "finance": (
        "erp",
        "payroll",
        "expense-system",
        "finance-drive",
    ),
    "hr": (
        "hrms",
        "payroll",
        "employee-directory",
        "document-store",
    ),
    "operations": (
        "monitoring-dashboard",
        "ticketing-system",
        "internal-api",
        "inventory-system",
    ),
}


class PersonaFactory:
    """Create reproducible behavioral personas."""

    def __init__(self, seed: int = 42) -> None:
        self._rng = np.random.default_rng(seed)

        Faker.seed(seed)
        self._faker = Faker()

    def create_users(
        self,
        count: int,
    ) -> list[BehavioralPersona]:
        if count <= 0:
            raise ValueError("count must be positive")

        return [
            self._create_user(index)
            for index in range(1, count + 1)
        ]

    def _create_user(
        self,
        index: int,
    ) -> BehavioralPersona:
        peer_group = str(
            self._rng.choice(
                list(_PEER_RESOURCES.keys())
            )
        )

        location = _LOCATIONS[
            int(self._rng.integers(0, len(_LOCATIONS)))
        ]

        login_hour = int(
            np.clip(
                self._rng.normal(9, 1.2),
                6,
                12,
            )
        )

        login_minute = int(
            self._rng.integers(0, 60)
        )

        number_of_devices = int(
            self._rng.integers(1, 4)
        )

        entity_id = f"USER_{index:05d}"

        devices = tuple(
            f"{entity_id}_DEVICE_{device_index}"
            for device_index in range(
                1,
                number_of_devices + 1,
            )
        )

        resources = _PEER_RESOURCES[peer_group]

        return BehavioralPersona(
            entity_id=entity_id,
            entity_type=EntityType.USER,
            peer_group=peer_group,
            home_location=location,
            typical_login_time=time(
                hour=login_hour,
                minute=login_minute,
            ),
            login_time_std_minutes=float(
                self._rng.uniform(20, 75)
            ),
            typical_session_minutes=float(
                self._rng.uniform(45, 180)
            ),
            session_std_minutes=float(
                self._rng.uniform(10, 35)
            ),
            known_device_ids=devices,
            common_resources=resources,
            auth_methods=(
                AuthMethod.SSO,
                AuthMethod.MFA,
            ),
            events_per_day_mean=float(
                self._rng.uniform(4, 12)
            ),
        )