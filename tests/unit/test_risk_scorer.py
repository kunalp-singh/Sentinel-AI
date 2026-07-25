from sentinel.detection import (
    AnomalyPrediction,
    HybridRiskScorer,
)


def normal_features() -> dict[str, float | int]:
    return {
        "failed_logins_10m": 0,
        "implied_speed_kmh": 0.0,
        "distance_from_previous_km": 0.0,
        "device_fingerprint_mismatch": 0,
        "source_ip_entity_fanout_10m": 1,
        "unique_resources_30m": 1,
        "resource_access_velocity_30m": 0.03,
        "is_new_resource": 0,
        "hour_deviation_zscore": 0.5,
        "session_duration_deviation_zscore": 0.5,
    }


def normal_prediction() -> AnomalyPrediction:
    return AnomalyPrediction(
        anomaly_score=-0.10,
        is_anomaly=False,
    )


def test_normal_behavior_has_low_risk() -> None:
    result = HybridRiskScorer().assess(
        normal_features(),
        normal_prediction(),
    )

    assert result.score < 30.0
    assert result.severity == "low"


def test_brute_force_increases_risk() -> None:
    features = normal_features()
    features["failed_logins_10m"] = 11

    result = HybridRiskScorer().assess(
        features,
        normal_prediction(),
    )

    assert result.score >= 30.0
    assert any(
        "failed logins" in reason
        for reason in result.reasons
    )


def test_impossible_travel_is_detected_without_ml_flag() -> None:
    features = normal_features()

    features["distance_from_previous_km"] = 9568.7
    features["implied_speed_kmh"] = 19137.4

    result = HybridRiskScorer().assess(
        features,
        AnomalyPrediction(
            anomaly_score=-0.0614,
            is_anomaly=False,
        ),
    )

    assert result.score >= 50.0

    assert any(
        "19137" in reason
        for reason in result.reasons
    )


def test_device_spoofing_increases_risk_without_ml_flag() -> None:
    features = normal_features()

    features["device_fingerprint_mismatch"] = 1

    result = HybridRiskScorer().assess(
        features,
        AnomalyPrediction(
            anomaly_score=-0.0467,
            is_anomaly=False,
        ),
    )

    assert result.score >= 40.0

    assert any(
        "fingerprint" in reason
        for reason in result.reasons
    )


def test_credential_stuffing_fanout_increases_risk() -> None:
    features = normal_features()

    features["source_ip_entity_fanout_10m"] = 8

    result = HybridRiskScorer().assess(
        features,
        normal_prediction(),
    )

    assert result.score >= 30.0


def test_lateral_movement_signals_increase_risk() -> None:
    features = normal_features()

    features["unique_resources_30m"] = 6
    features["is_new_resource"] = 1
    features["resource_access_velocity_30m"] = 0.25

    result = HybridRiskScorer().assess(
        features,
        normal_prediction(),
    )

    assert result.score >= 40.0


def test_ml_anomaly_contributes_to_risk() -> None:
    result = HybridRiskScorer().assess(
        normal_features(),
        AnomalyPrediction(
            anomaly_score=0.08,
            is_anomaly=True,
        ),
    )

    assert result.ml_contribution > 0.0

    assert any(
        "Isolation Forest" in reason
        for reason in result.reasons
    )


def test_risk_score_is_capped_at_100() -> None:
    features = normal_features()

    features.update(
        {
            "failed_logins_10m": 20,
            "implied_speed_kmh": 20000.0,
            "distance_from_previous_km": 10000.0,
            "device_fingerprint_mismatch": 1,
            "source_ip_entity_fanout_10m": 10,
            "unique_resources_30m": 10,
            "resource_access_velocity_30m": 1.0,
            "is_new_resource": 1,
            "hour_deviation_zscore": 8.0,
            "session_duration_deviation_zscore": 8.0,
        }
    )

    result = HybridRiskScorer().assess(
        features,
        AnomalyPrediction(
            anomaly_score=0.50,
            is_anomaly=True,
        ),
    )

    assert result.score == 100.0
    assert result.severity == "critical"