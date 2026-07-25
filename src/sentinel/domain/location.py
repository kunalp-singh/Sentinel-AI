from pydantic import BaseModel, ConfigDict, Field


class GeoLocation(BaseModel):
    """Geographic origin associated with a security event."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    country_code: str = Field(
        min_length=2,
        max_length=2,
        pattern=r"^[A-Z]{2}$",
    )

    city: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    latitude: float = Field(ge=-90.0, le=90.0)
    longitude: float = Field(ge=-180.0, le=180.0)