from collections import Counter

from sentinel.classification import (
    AnomalyType,
    AnomalyTypeClassifier,
)


def base_features() -> dict[str, float]:
    """Return neutral behavioral features."""

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


def build_evaluation_cases() -> list[
    tuple[AnomalyType, dict[str, float]]
]:
    """Build representative attack cases."""

    cases: list[
        tuple[AnomalyType, dict[str, float]]
    ] = []

    # Brute force
    for failures in range(5, 12):
        features = base_features()
        features["failed_logins_10m"] = float(failures)
        features["events_10m"] = float(failures + 2)

        cases.append(
            (
                AnomalyType.BRUTE_FORCE,
                features,
            )
        )

    # Credential stuffing
    for fanout in range(4, 10):
        features = base_features()
        features[
            "source_ip_entity_fanout_10m"
        ] = float(fanout)
        features["failed_logins_10m"] = 2.0

        cases.append(
            (
                AnomalyType.CREDENTIAL_STUFFING,
                features,
            )
        )

    # Impossible travel
    travel_cases = [
        (4500.0, 9000.0),
        (8000.0, 5000.0),
        (12000.0, 7000.0),
        (19000.0, 9500.0),
    ]

    for speed, distance in travel_cases:
        features = base_features()
        features["implied_speed_kmh"] = speed
        features[
            "distance_from_previous_km"
        ] = distance

        cases.append(
            (
                AnomalyType.IMPOSSIBLE_TRAVEL,
                features,
            )
        )

    # Lateral movement
    lateral_cases = [
        (4.0, 0.15),
        (5.0, 0.18),
        (6.0, 0.20),
        (8.0, 0.25),
    ]

    for resources, velocity in lateral_cases:
        features = base_features()
        features[
            "unique_resources_30m"
        ] = resources
        features[
            "resource_access_velocity_30m"
        ] = velocity
        features["is_new_resource"] = 1.0

        cases.append(
            (
                AnomalyType.LATERAL_MOVEMENT,
                features,
            )
        )

    # Device spoofing
    for _ in range(4):
        features = base_features()

        features[
            "device_fingerprint_mismatch"
        ] = 1.0

        cases.append(
            (
                AnomalyType.DEVICE_SPOOFING,
                features,
            )
        )

    return cases


def main() -> None:
    classifier = AnomalyTypeClassifier()

    cases = build_evaluation_cases()

    totals: Counter[AnomalyType] = Counter()
    correct: Counter[AnomalyType] = Counter()

    overall_correct = 0

    for expected, features in cases:
        result = classifier.classify(
            features,
            is_suspicious=True,
        )

        totals[expected] += 1

        if result.anomaly_type == expected:
            correct[expected] += 1
            overall_correct += 1

    print()
    print("=" * 58)
    print("       SENTINELAI ANOMALY CLASSIFICATION")
    print("=" * 58)

    print()
    print(
        f"{'Attack':<25}"
        f"{'Correct':>10}"
        f"{'Accuracy':>15}"
    )
    print("-" * 58)

    attack_types = [
        AnomalyType.BRUTE_FORCE,
        AnomalyType.CREDENTIAL_STUFFING,
        AnomalyType.IMPOSSIBLE_TRAVEL,
        AnomalyType.LATERAL_MOVEMENT,
        AnomalyType.DEVICE_SPOOFING,
    ]

    for attack_type in attack_types:
        attack_total = totals[attack_type]
        attack_correct = correct[attack_type]

        accuracy = (
            attack_correct / attack_total
            if attack_total
            else 0.0
        )

        print(
            f"{attack_type.value:<25}"
            f"{attack_correct:>4}/{attack_total:<5}"
            f"{accuracy:>14.1%}"
        )

    overall_accuracy = overall_correct / len(cases)

    print("-" * 58)

    print(
        f"{'Overall':<25}"
        f"{overall_correct:>4}/{len(cases):<5}"
        f"{overall_accuracy:>14.1%}"
    )

    print("=" * 58)
    print()


if __name__ == "__main__":
    main()