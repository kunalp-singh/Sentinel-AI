from dataclasses import dataclass

from sentinel.detection.isolation_forest import AnomalyPrediction


@dataclass(frozen=True)
class RiskAssessment:
    """Explainable hybrid security risk assessment."""

    score: float
    severity: str
    reasons: tuple[str, ...]
    ml_contribution: float
    behavioral_contribution: float


class HybridRiskScorer:
    """Combine ML anomaly evidence with security-specific signals."""

    MAX_SCORE = 100.0

    def assess(
        self,
        features: dict[str, float | int],
        prediction: AnomalyPrediction,
    ) -> RiskAssessment:
        behavioral_score = 0.0
        reasons: list[str] = []

        # --------------------------------------------------
        # Brute-force behavior
        # --------------------------------------------------

        failed_logins = int(
            features.get("failed_logins_10m", 0)
        )

        if failed_logins >= 10:
            behavioral_score += 35.0
            reasons.append(
                f"{failed_logins} failed logins "
                "occurred within 10 minutes"
            )
        elif failed_logins >= 5:
            behavioral_score += 20.0
            reasons.append(
                f"{failed_logins} failed logins "
                "occurred within 10 minutes"
            )

        # --------------------------------------------------
        # Impossible travel
        # --------------------------------------------------

        implied_speed = float(
            features.get("implied_speed_kmh", 0.0)
        )

        distance = float(
            features.get(
                "distance_from_previous_km",
                0.0,
            )
        )

        if implied_speed >= 1000.0:
            behavioral_score += 45.0
            reasons.append(
                "Travel between consecutive events "
                f"would require {implied_speed:.0f} km/h"
            )
        elif implied_speed >= 500.0:
            behavioral_score += 25.0
            reasons.append(
                "Unusually high travel speed "
                f"of {implied_speed:.0f} km/h"
            )

        if distance >= 3000.0:
            behavioral_score += 10.0
            reasons.append(
                "Consecutive activity occurred "
                f"{distance:.0f} km apart"
            )

        # --------------------------------------------------
        # Device spoofing
        # --------------------------------------------------

        fingerprint_mismatch = int(
            features.get(
                "device_fingerprint_mismatch",
                0,
            )
        )

        if fingerprint_mismatch == 1:
            behavioral_score += 40.0
            reasons.append(
                "Known device identifier presented "
                "an unexpected fingerprint"
            )

        # --------------------------------------------------
        # Credential stuffing
        # --------------------------------------------------

        fanout = int(
            features.get(
                "source_ip_entity_fanout_10m",
                0,
            )
        )

        if fanout >= 5:
            behavioral_score += 35.0
            reasons.append(
                "A single source IP accessed "
                f"{fanout} entities within 10 minutes"
            )
        elif fanout >= 3:
            behavioral_score += 20.0
            reasons.append(
                "Source IP accessed multiple entities "
                "within a short period"
            )

        # --------------------------------------------------
        # Lateral movement
        # --------------------------------------------------

        unique_resources = int(
            features.get(
                "unique_resources_30m",
                0,
            )
        )

        resource_velocity = float(
            features.get(
                "resource_access_velocity_30m",
                0.0,
            )
        )

        is_new_resource = int(
            features.get(
                "is_new_resource",
                0,
            )
        )

        if (
            unique_resources >= 5
            and is_new_resource == 1
        ):
            behavioral_score += 30.0
            reasons.append(
                "Entity rapidly accessed multiple "
                "resources including an unfamiliar resource"
            )

        if resource_velocity >= 0.20:
            behavioral_score += 10.0
            reasons.append(
                "Resource access velocity is unusually high"
            )

        # --------------------------------------------------
        # Profile deviations
        # --------------------------------------------------

        hour_zscore = float(
            features.get(
                "hour_deviation_zscore",
                0.0,
            )
        )

        if hour_zscore >= 3.0:
            behavioral_score += 10.0
            reasons.append(
                "Activity occurred far outside the "
                "entity's typical access hours"
            )

        session_zscore = float(
            features.get(
                "session_duration_deviation_zscore",
                0.0,
            )
        )

        if session_zscore >= 3.0:
            behavioral_score += 10.0
            reasons.append(
                "Session duration strongly deviates "
                "from the entity's normal behavior"
            )

        # --------------------------------------------------
        # ML contribution
        # --------------------------------------------------

        ml_contribution = self._ml_contribution(
            prediction
        )

        if prediction.is_anomaly:
            reasons.append(
                "Isolation Forest classified the "
                "event as statistically anomalous"
            )

        # Cap behavioral evidence independently.
        behavioral_contribution = min(
            behavioral_score,
            80.0,
        )

        total_score = min(
            behavioral_contribution
            + ml_contribution,
            self.MAX_SCORE,
        )

        severity = self._severity(total_score)

        if not reasons:
            reasons.append(
                "No significant behavioral risk "
                "signals were observed"
            )

        return RiskAssessment(
            score=total_score,
            severity=severity,
            reasons=tuple(reasons),
            ml_contribution=ml_contribution,
            behavioral_contribution=(
                behavioral_contribution
            ),
        )

    @staticmethod
    def _ml_contribution(
        prediction: AnomalyPrediction,
    ) -> float:
        """
        Convert Isolation Forest evidence into at most
        20 risk points.

        Positive SentinelAI anomaly scores represent
        stronger statistical anomaly evidence.
        """

        score = prediction.anomaly_score

        if prediction.is_anomaly:
            return min(
                10.0 + max(score, 0.0) * 100.0,
                20.0,
            )

        if score >= -0.025:
            return 5.0

        return 0.0

    @staticmethod
    def _severity(
        score: float,
    ) -> str:
        if score >= 80.0:
            return "critical"

        if score >= 60.0:
            return "high"

        if score >= 30.0:
            return "medium"

        return "low"