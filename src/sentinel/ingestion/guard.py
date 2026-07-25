import json
from collections.abc import Mapping, Sequence
from typing import Any

from sentinel.exceptions import SecurityError
from sentinel.ingestion.limits import IngestionLimits


class PayloadGuard:
    """Reject structurally unsafe telemetry before validation."""

    def __init__(self, limits: IngestionLimits | None = None) -> None:
        self._limits = limits or IngestionLimits()

    def validate(self, payload: Mapping[str, Any]) -> None:
        """Validate payload size and structural complexity."""

        self._validate_serialized_size(payload)
        self._validate_structure(payload)

    def _validate_serialized_size(
        self,
        payload: Mapping[str, Any],
    ) -> None:
        try:
            serialized = json.dumps(
                payload,
                default=str,
                ensure_ascii=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise SecurityError(
                "Payload cannot be safely serialized"
            ) from exc

        if len(serialized) > self._limits.max_payload_bytes:
            raise SecurityError(
                "Payload exceeds maximum allowed size"
            )

    def _validate_structure(
        self,
        value: Any,
        depth: int = 0,
    ) -> None:
        if depth > self._limits.max_nesting_depth:
            raise SecurityError(
                "Payload exceeds maximum nesting depth"
            )

        if isinstance(value, str):
            if len(value) > self._limits.max_string_length:
                raise SecurityError(
                    "Payload contains an oversized string"
                )

            return

        if isinstance(value, Mapping):
            if len(value) > self._limits.max_collection_items:
                raise SecurityError(
                    "Payload contains too many mapping entries"
                )

            for key, item in value.items():
                if not isinstance(key, str):
                    raise SecurityError(
                        "Payload mapping keys must be strings"
                    )

                self._validate_structure(
                    item,
                    depth + 1,
                )

            return

        if isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            if len(value) > self._limits.max_collection_items:
                raise SecurityError(
                    "Payload contains too many collection items"
                )

            for item in value:
                self._validate_structure(
                    item,
                    depth + 1,
                )