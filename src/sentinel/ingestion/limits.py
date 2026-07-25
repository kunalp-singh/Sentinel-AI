from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IngestionLimits:
    """Security limits applied to incoming telemetry."""

    max_payload_bytes: int = 64 * 1024
    max_string_length: int = 10_000
    max_nesting_depth: int = 10
    max_collection_items: int = 500