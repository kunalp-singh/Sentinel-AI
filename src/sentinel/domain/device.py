from pydantic import BaseModel, ConfigDict, Field


class DeviceFingerprint(BaseModel):
    """Normalized characteristics used to identify a device."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    fingerprint_id: str = Field(min_length=8, max_length=128)

    operating_system: str | None = Field(
        default=None,
        max_length=64,
    )

    browser: str | None = Field(
        default=None,
        max_length=64,
    )

    device_type: str | None = Field(
        default=None,
        max_length=64,
    )