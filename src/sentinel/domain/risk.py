from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinel.domain.enums import Severity


class RiskScore(BaseModel):
    """Deterministic normalized risk assessment."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity

    @model_validator(mode="after")
    def validate_severity(self) -> "RiskScore":
        expected: Severity

        if self.score >= 85:
            expected = Severity.CRITICAL
        elif self.score >= 65:
            expected = Severity.HIGH
        elif self.score >= 35:
            expected = Severity.MEDIUM
        else:
            expected = Severity.LOW

        if self.severity != expected:
            raise ValueError(
                f"severity '{self.severity}' does not match "
                f"risk score {self.score}; expected '{expected}'"
            )

        return self