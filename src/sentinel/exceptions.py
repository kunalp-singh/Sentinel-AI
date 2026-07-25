class SentinelError(Exception):
    """Base exception for all SentinelAI-specific errors."""


class ConfigurationError(SentinelError):
    """Raised when application configuration is invalid."""


class EventValidationError(SentinelError):
    """Raised when incoming security telemetry fails validation."""


class DetectionError(SentinelError):
    """Raised when the detection pipeline cannot process an event."""


class ModelError(SentinelError):
    """Raised when an ML model operation fails."""


class SecurityError(SentinelError):
    """Raised when a security constraint is violated."""