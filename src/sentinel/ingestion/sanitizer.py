import re
import unicodedata
from collections.abc import Mapping
from typing import Any

_CONTROL_CHARACTERS = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)


class EventSanitizer:
    """Normalize untrusted telemetry without destroying evidence."""

    def sanitize(
        self,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Return a recursively sanitized copy of the payload."""

        return {
            key: self._sanitize_value(value)
            for key, value in payload.items()
        }

    def _sanitize_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._sanitize_string(value)

        if isinstance(value, Mapping):
            return {
                str(key): self._sanitize_value(item)
                for key, item in value.items()
            }

        if isinstance(value, list):
            return [
                self._sanitize_value(item)
                for item in value
            ]

        if isinstance(value, tuple):
            return [
                self._sanitize_value(item)
                for item in value
            ]

        return value

    @staticmethod
    def _sanitize_string(value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value)

        return _CONTROL_CHARACTERS.sub("", normalized)