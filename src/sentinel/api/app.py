from fastapi import FastAPI, HTTPException

from sentinel.api.schemas import (
    AnalysisResponse,
    HealthResponse,
    RootResponse,
)
from sentinel.api.service import (
    SentinelAnalysisService,
)
from sentinel.domain import SecurityEvent

APP_VERSION = "0.1.0"

app = FastAPI(
    title="SentinelAI",
    description=(
        "Behavioral anomaly detection and "
        "explainable security risk assessment API."
    ),
    version=APP_VERSION,
)


analysis_service = SentinelAnalysisService()


@app.get(
    "/",
    response_model=RootResponse,
    tags=["system"],
)
def root() -> RootResponse:
    """Return basic SentinelAI service information."""

    return RootResponse(
        service="SentinelAI",
        description=(
            "Behavioral anomaly detection and "
            "explainable security risk assessment."
        ),
        version=APP_VERSION,
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["system"],
)
def health() -> HealthResponse:
    """Return application health status."""

    return HealthResponse(
        status="healthy",
        service="SentinelAI",
        version=APP_VERSION,
    )


@app.post(
    "/analyze",
    response_model=AnalysisResponse,
    tags=["detection"],
)
def analyze(
    event: SecurityEvent,
) -> AnalysisResponse:
    """Analyze a telemetry event for behavioral risk."""

    try:
        result = analysis_service.analyze(event)

        explanation = result.explanation
        classification = result.classification

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    return AnalysisResponse(
        event_id=explanation.event_id,
        entity_id=explanation.entity_id,
        risk_score=explanation.risk_score,
        severity=explanation.severity,
        is_suspicious=(
            explanation.risk_score >= 30.0
        ),
        summary=explanation.summary,
        reasons=list(
            explanation.reasons
        ),
        ml_anomaly_score=(
            explanation.ml_anomaly_score
        ),
        ml_flagged=explanation.ml_flagged,
        ml_contribution=(
            explanation.ml_contribution
        ),
        behavioral_contribution=(
            explanation.behavioral_contribution
        ),
        anomaly_type=classification.anomaly_type.value,
        classification_confidence=classification.confidence,
        classification_evidence=list(
            classification.evidence
        ),
    )