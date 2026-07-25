from collections.abc import Mapping
from typing import Any

from sentinel.domain import SecurityEvent
from sentinel.ingestion.guard import PayloadGuard
from sentinel.ingestion.sanitizer import EventSanitizer
from sentinel.ingestion.validator import EventValidator


class EventIngestionPipeline:
    """Secure boundary for incoming SentinelAI telemetry."""

    def __init__(
        self,
        guard: PayloadGuard | None = None,
        sanitizer: EventSanitizer | None = None,
        validator: EventValidator | None = None,
    ) -> None:
        self._guard = guard or PayloadGuard()
        self._sanitizer = sanitizer or EventSanitizer()
        self._validator = validator or EventValidator()

    def ingest(
        self,
        payload: Mapping[str, Any],
    ) -> SecurityEvent:
        """Convert untrusted telemetry into a validated event."""

        self._guard.validate(payload)

        sanitized = self._sanitizer.sanitize(payload)

        return self._validator.validate(sanitized)