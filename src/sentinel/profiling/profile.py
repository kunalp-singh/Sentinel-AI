from pydantic import BaseModel, ConfigDict, Field


class DeviceProfile(BaseModel):
    """Observed fingerprint associated with a device identifier."""

    model_config = ConfigDict(frozen=True)

    fingerprint_id: str
    operating_system: str | None = None
    browser: str | None = None
    device_type: str | None = None


class EntityBehaviorProfile(BaseModel):
    """Learned historical behavioral baseline for one entity."""

    model_config = ConfigDict(frozen=True)

    entity_id: str
    event_count: int = Field(gt=0)

    mean_hour: float = Field(ge=0.0, le=23.0)
    hour_std: float = Field(ge=0.0)

    mean_session_duration: float = Field(ge=0.0)
    session_duration_std: float = Field(ge=0.0)

    authentication_failure_rate: float = Field(
        ge=0.0,
        le=1.0,
    )

    known_source_ips: frozenset[str]
    known_resources: frozenset[str]
    known_auth_methods: frozenset[str]
    known_devices: tuple[DeviceProfile, ...]