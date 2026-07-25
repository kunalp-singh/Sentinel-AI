from typing import Literal

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    """Health-check response returned by SentinelAI."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["healthy"]
    service: str
    version: str


class RootResponse(BaseModel):
    """Basic SentinelAI service information."""

    model_config = ConfigDict(extra="forbid")

    service: str
    description: str
    version: str