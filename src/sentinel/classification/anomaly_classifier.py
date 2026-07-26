from dataclasses import dataclass
from enum import StrEnum


class AnomalyType(StrEnum):
    """Attack categories currently recognized by SentinelAI."""

    NORMAL = "normal"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    LATERAL_MOVEMENT = "lateral_movement"
    DEVICE_SPOOFING = "device_spoofing"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ClassificationResult:
    """Explainable anomaly classification."""

    anomaly_type: AnomalyType
    confidence: float
    evidence: tuple[str, ...]


class AnomalyTypeClassifier:
    """Classify suspicious behavior using deterministic signals."""

    @staticmethod
    def _value(
        features: dict[str, float],
        name: str,
    ) -> float:
        return float(features.get(name, 0.0))

    def classify(
        self,
        features: dict[str, float],
        *,
        is_suspicious: bool,
    ) -> ClassificationResult:
        """Return the attack pattern most strongly supported."""

        if not is_suspicious:
            return ClassificationResult(
                anomaly_type=AnomalyType.NORMAL,
                confidence=1.0,
                evidence=(),
            )

        scores: dict[AnomalyType, float] = {
            AnomalyType.BRUTE_FORCE: 0.0,
            AnomalyType.CREDENTIAL_STUFFING: 0.0,
            AnomalyType.IMPOSSIBLE_TRAVEL: 0.0,
            AnomalyType.LATERAL_MOVEMENT: 0.0,
            AnomalyType.DEVICE_SPOOFING: 0.0,
        }

        evidence: dict[AnomalyType, list[str]] = {
            attack_type: []
            for attack_type in scores
        }

        failed_logins = self._value(
            features,
            "failed_logins_10m",
        )

        events_10m = self._value(
            features,
            "events_10m",
        )

        fanout = self._value(
            features,
            "source_ip_entity_fanout_10m",
        )

        implied_speed = self._value(
            features,
            "implied_speed_kmh",
        )

        distance = self._value(
            features,
            "distance_from_previous_km",
        )

        fingerprint_mismatch = self._value(
            features,
            "device_fingerprint_mismatch",
        )

        is_new_device = self._value(
            features,
            "is_new_device",
        )

        is_new_resource = self._value(
            features,
            "is_new_resource",
        )

        unique_resources = self._value(
            features,
            "unique_resources_30m",
        )

        resource_velocity = self._value(
            features,
            "resource_access_velocity_30m",
        )

        # Brute force:
        # repeated authentication failures concentrated
        # against an entity in a short time window.
        if failed_logins >= 5:
            scores[AnomalyType.BRUTE_FORCE] += 0.65
            evidence[AnomalyType.BRUTE_FORCE].append(
                f"{failed_logins:.0f} failed logins "
                "occurred within 10 minutes"
            )

        if events_10m >= 6:
            scores[AnomalyType.BRUTE_FORCE] += 0.20
            evidence[AnomalyType.BRUTE_FORCE].append(
                f"{events_10m:.0f} events occurred "
                "within 10 minutes"
            )

        # Credential stuffing:
        # one source IP interacting with several identities.
        if fanout >= 4:
            scores[
                AnomalyType.CREDENTIAL_STUFFING
            ] += 0.70

            evidence[
                AnomalyType.CREDENTIAL_STUFFING
            ].append(
                "Source IP accessed "
                f"{fanout:.0f} entities within 10 minutes"
            )

        if fanout >= 4 and failed_logins >= 1:
            scores[
                AnomalyType.CREDENTIAL_STUFFING
            ] += 0.20

            evidence[
                AnomalyType.CREDENTIAL_STUFFING
            ].append(
                "Multi-entity activity included "
                "authentication failures"
            )

        # Impossible travel.
        if implied_speed >= 1000:
            scores[
                AnomalyType.IMPOSSIBLE_TRAVEL
            ] += 0.75

            evidence[
                AnomalyType.IMPOSSIBLE_TRAVEL
            ].append(
                "Travel would require "
                f"{implied_speed:.0f} km/h"
            )

        if distance >= 3000:
            scores[
                AnomalyType.IMPOSSIBLE_TRAVEL
            ] += 0.20

            evidence[
                AnomalyType.IMPOSSIBLE_TRAVEL
            ].append(
                "Consecutive activity occurred "
                f"{distance:.0f} km apart"
            )

        # Device spoofing.
        if fingerprint_mismatch >= 1:
            scores[
                AnomalyType.DEVICE_SPOOFING
            ] += 0.80

            evidence[
                AnomalyType.DEVICE_SPOOFING
            ].append(
                "Known device ID presented a "
                "different fingerprint"
            )

        if fingerprint_mismatch >= 1 and is_new_device >= 1:
            scores[
                AnomalyType.DEVICE_SPOOFING
            ] += 0.10

        # Lateral movement.
        if unique_resources >= 4:
            scores[
                AnomalyType.LATERAL_MOVEMENT
            ] += 0.40

            evidence[
                AnomalyType.LATERAL_MOVEMENT
            ].append(
                f"{unique_resources:.0f} unique resources "
                "were accessed within 30 minutes"
            )

        if resource_velocity >= 0.15:
            scores[
                AnomalyType.LATERAL_MOVEMENT
            ] += 0.30

            evidence[
                AnomalyType.LATERAL_MOVEMENT
            ].append(
                "Resource access velocity was unusually high"
            )

        if is_new_resource >= 1:
            scores[
                AnomalyType.LATERAL_MOVEMENT
            ] += 0.20

            evidence[
                AnomalyType.LATERAL_MOVEMENT
            ].append(
                "Entity accessed a resource outside "
                "its behavioral baseline"
            )

        best_type = max(
            scores,
            key=lambda attack_type: scores[attack_type],
        )

        best_score = min(scores[best_type], 1.0)

        # Suspicious event, but no attack signature
        # has enough evidence for a useful classification.
        if best_score < 0.40:
            return ClassificationResult(
                anomaly_type=AnomalyType.UNKNOWN,
                confidence=best_score,
                evidence=(),
            )

        return ClassificationResult(
            anomaly_type=best_type,
            confidence=best_score,
            evidence=tuple(evidence[best_type]),
        )