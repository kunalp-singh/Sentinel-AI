from enum import StrEnum


class EntityType(StrEnum):
    """Types of entities monitored by SentinelAI."""

    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    EDGE_DEVICE = "edge_device"


class AuthMethod(StrEnum):
    """Supported authentication mechanisms."""

    PASSWORD = "password"
    SSO = "sso"
    MFA = "mfa"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"


class EventOutcome(StrEnum):
    """Outcome of an access/authentication event."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class ThreatLabel(StrEnum):
    """Ground-truth labels used primarily for synthetic data/evaluation."""

    NORMAL = "normal"
    BRUTE_FORCE = "brute_force"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    CREDENTIAL_STUFFING = "credential_stuffing"
    LATERAL_MOVEMENT = "lateral_movement"
    DEVICE_SPOOFING = "device_spoofing"
    LOW_SLOW_EXFILTRATION = "low_slow_exfiltration"
    INSIDER_DRIFT = "insider_drift"


class Severity(StrEnum):
    """Human-facing alert severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    """Lifecycle state of an alert."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONFIRMED_THREAT = "confirmed_threat"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"