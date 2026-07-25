from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
)

from sentinel.domain.device import DeviceFingerprint
from sentinel.domain.enums import (
    AuthMethod,
    EntityType,
    EventOutcome,
    ThreatLabel,
)
from sentinel.domain.location import GeoLocation


class SecurityEvent(BaseModel):
    """Validated security telemetry entering SentinelAI."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    event_id: str = Field(min_length=8, max_length=64)

    entity_id: str = Field(min_length=3, max_length=64)
    entity_type: EntityType

    timestamp: datetime

    source_ip: IPvAnyAddress
    geo_location: GeoLocation

    resource_accessed: str = Field(
        min_length=1,
        max_length=256,
    )

    auth_method: AuthMethod
    outcome: EventOutcome

    session_duration_seconds: int = Field(
        ge=0,
        le=86_400,
    )

    command_sequence: list[str] = Field(
        default_factory=list,
        max_length=100,
    )

    device_fingerprint: DeviceFingerprint

    label: ThreatLabel | None = None

    @field_validator("command_sequence")
    @classmethod
    def validate_commands(cls, commands: list[str]) -> list[str]:
        for command in commands:
            if not command.strip():
                raise ValueError("command_sequence cannot contain empty commands")

            if len(command) > 500:
                raise ValueError(
                    "individual commands cannot exceed 500 characters"
                )

        return commands