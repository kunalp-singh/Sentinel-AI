from sentinel.classification import (
    AnomalyType,
    AnomalyTypeClassifier,
)


def base_features() -> dict[str, float]:
    return {
        "failed_logins_10m": 0.0,
        "events_10m": 1.0,
        "source_ip_entity_fanout_10m": 1.0,
        "implied_speed_kmh": 0.0,
        "distance_from_previous_km": 0.0,
        "device_fingerprint_mismatch": 0.0,
        "is_new_device": 0.0,
        "is_new_resource": 0.0,
        "unique_resources_30m": 1.0,
        "resource_access_velocity_30m": 0.03,
    }


def test_normal_event_is_classified_normal() -> None:
    result = AnomalyTypeClassifier().classify(
        base_features(),
        is_suspicious=False,
    )

    assert result.anomaly_type == AnomalyType.NORMAL
    assert result.confidence == 1.0


def test_classifies_brute_force() -> None:
    features = base_features()

    features["failed_logins_10m"] = 9.0
    features["events_10m"] = 11.0

    result = AnomalyTypeClassifier().classify(
        features,
        is_suspicious=True,
    )

    assert result.anomaly_type == AnomalyType.BRUTE_FORCE
    assert result.confidence >= 0.8
    assert result.evidence


def test_classifies_credential_stuffing() -> None:
    features = base_features()

    features["source_ip_entity_fanout_10m"] = 8.0
    features["failed_logins_10m"] = 3.0

    result = AnomalyTypeClassifier().classify(
        features,
        is_suspicious=True,
    )

    assert (
        result.anomaly_type
        == AnomalyType.CREDENTIAL_STUFFING
    )


def test_classifies_impossible_travel() -> None:
    features = base_features()

    features["implied_speed_kmh"] = 19137.0
    features["distance_from_previous_km"] = 9569.0

    result = AnomalyTypeClassifier().classify(
        features,
        is_suspicious=True,
    )

    assert (
        result.anomaly_type
        == AnomalyType.IMPOSSIBLE_TRAVEL
    )

    assert result.confidence >= 0.9


def test_classifies_device_spoofing() -> None:
    features = base_features()

    features["device_fingerprint_mismatch"] = 1.0

    result = AnomalyTypeClassifier().classify(
        features,
        is_suspicious=True,
    )

    assert (
        result.anomaly_type
        == AnomalyType.DEVICE_SPOOFING
    )


def test_classifies_lateral_movement() -> None:
    features = base_features()

    features["unique_resources_30m"] = 6.0
    features[
        "resource_access_velocity_30m"
    ] = 0.20
    features["is_new_resource"] = 1.0

    result = AnomalyTypeClassifier().classify(
        features,
        is_suspicious=True,
    )

    assert (
        result.anomaly_type
        == AnomalyType.LATERAL_MOVEMENT
    )


def test_unknown_when_signature_is_weak() -> None:
    result = AnomalyTypeClassifier().classify(
        base_features(),
        is_suspicious=True,
    )

    assert result.anomaly_type == AnomalyType.UNKNOWN