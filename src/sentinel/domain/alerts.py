from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from sentinel.domain.enums import AlertStatus
from sentinel.domain.risk import RiskScore


class RiskEvidence(BaseModel):
    """One explainable contribution to an alert."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    signal: str = Field(min_length=1, max_length=100)
    contribution: float = Field(ge=0.0, le=100.0)
    description: str = Field(min_length=1, max_length=500)


class Alert(BaseModel):
    """Security alert generated from suspicious behaviour."""

    model_config = ConfigDict(
        extra="forbid",
    )

    alert_id: str = Field(min_length=8, max_length=64)
    event_id: str = Field(min_length=8, max_length=64)
    entity_id: str = Field(min_length=3, max_length=64)

    risk: RiskScore

    classification: str | None = Field(
        default=None,
        max_length=100,
    )

    evidence: list[RiskEvidence] = Field(
        default_factory=list,
        max_length=20,
    )

    status: AlertStatus = AlertStatus.OPEN

    created_at: datetime = Field(
    default_factory=lambda: datetime.now(UTC)
    )