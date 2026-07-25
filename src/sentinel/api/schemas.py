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

class AnalysisResponse(BaseModel):
    """SentinelAI security analysis response."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    entity_id: str

    risk_score: float
    severity: str
    is_suspicious: bool

    summary: str
    reasons: list[str]

    ml_anomaly_score: float
    ml_flagged: bool

    ml_contribution: float
    behavioral_contribution: float