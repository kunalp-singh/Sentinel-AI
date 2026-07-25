from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from sentinel.domain import SecurityEvent
from sentinel.exceptions import EventValidationError


class EventValidator:
    """Convert sanitized telemetry into trusted domain objects."""

    def validate(
        self,
        payload: Mapping[str, Any],
    ) -> SecurityEvent:
        try:
            return SecurityEvent.model_validate(payload)

        except ValidationError as exc:
            raise EventValidationError(
                "Security event failed schema validation"
            ) from exc