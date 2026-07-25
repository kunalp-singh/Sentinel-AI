from fastapi import FastAPI

from sentinel.api.schemas import (
    HealthResponse,
    RootResponse,
)

APP_VERSION = "0.1.0"

app = FastAPI(
    title="SentinelAI",
    description=(
        "Behavioral anomaly detection and "
        "explainable security risk assessment API."
    ),
    version=APP_VERSION,
)


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