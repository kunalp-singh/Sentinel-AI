from dataclasses import dataclass

from sentinel.detection import (
    AnomalyPrediction,
    RiskAssessment,
)
from sentinel.domain import SecurityEvent


@dataclass(frozen=True)
class SecurityExplanation:
    """Human-readable explanation of a security assessment."""

    event_id: str
    entity_id: str
    risk_score: float
    severity: str

    summary: str
    reasons: tuple[str, ...]

    ml_anomaly_score: float
    ml_flagged: bool

    ml_contribution: float
    behavioral_contribution: float


class SecurityExplainer:
    """Generate deterministic explanations from security evidence."""

    def explain(
        self,
        event: SecurityEvent,
        assessment: RiskAssessment,
        prediction: AnomalyPrediction,
    ) -> SecurityExplanation:
        summary = self._build_summary(
            assessment,
        )

        return SecurityExplanation(
            event_id=str(event.event_id),
            entity_id=event.entity_id,
            risk_score=assessment.score,
            severity=assessment.severity,
            summary=summary,
            reasons=assessment.reasons,
            ml_anomaly_score=prediction.anomaly_score,
            ml_flagged=prediction.is_anomaly,
            ml_contribution=assessment.ml_contribution,
            behavioral_contribution=(
                assessment.behavioral_contribution
            ),
        )

    @staticmethod
    def _build_summary(
        assessment: RiskAssessment,
    ) -> str:
        severity = assessment.severity.upper()
        score = assessment.score

        if assessment.severity == "critical":
            return (
                f"{severity} risk activity detected "
                f"with a risk score of {score:.0f}/100. "
                "Immediate investigation is recommended."
            )

        if assessment.severity == "high":
            return (
                f"{severity} risk activity detected "
                f"with a risk score of {score:.0f}/100. "
                "Multiple suspicious behavioral signals "
                "require investigation."
            )

        if assessment.severity == "medium":
            return (
                f"{severity} risk activity detected "
                f"with a risk score of {score:.0f}/100. "
                "Behavioral deviations warrant review."
            )

        return (
            f"{severity} risk activity observed "
            f"with a risk score of {score:.0f}/100. "
            "No significant threat indicators were detected."
        )