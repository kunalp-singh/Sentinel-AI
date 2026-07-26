from dataclasses import dataclass
from math import ceil

import pandas as pd


@dataclass(frozen=True)
class AlertBudgetResult:
    """Metrics for a ranked analyst alert budget."""

    total_events: int
    total_attacks: int
    budget_fraction: float
    alert_count: int
    true_alerts: int
    false_alerts: int
    precision_at_budget: float
    attack_recall_at_budget: float
    false_positive_rate: float
    attack_types_surfaced: tuple[str, ...]


class AlertBudgetEvaluator:
    """Evaluate ranked risk scores under a fixed alert budget."""

    def evaluate(
        self,
        results: pd.DataFrame,
        *,
        budget_fraction: float = 0.01,
    ) -> AlertBudgetResult:
        if results.empty:
            raise ValueError(
                "cannot evaluate an empty result set"
            )

        if not 0.0 < budget_fraction <= 1.0:
            raise ValueError(
                "budget_fraction must be in (0, 1]"
            )

        required_columns = {
            "risk_score",
            "label",
        }

        missing = required_columns - set(results.columns)

        if missing:
            raise ValueError(
                "missing required columns: "
                + ", ".join(sorted(missing))
            )

        ranked = results.sort_values(
            by="risk_score",
            ascending=False,
        ).reset_index(drop=True)

        alert_count = max(
            1,
            ceil(len(ranked) * budget_fraction),
        )

        alerts = ranked.head(alert_count)

        attack_mask = ranked["label"] != "normal"
        alert_attack_mask = alerts["label"] != "normal"

        total_attacks = int(attack_mask.sum())
        total_normal = len(ranked) - total_attacks

        true_alerts = int(alert_attack_mask.sum())
        false_alerts = alert_count - true_alerts

        precision = (
            true_alerts / alert_count
            if alert_count
            else 0.0
        )

        recall = (
            true_alerts / total_attacks
            if total_attacks
            else 0.0
        )

        false_positive_rate = (
            false_alerts / total_normal
            if total_normal
            else 0.0
        )

        surfaced = tuple(
            sorted(
                {
                    str(label)
                    for label in alerts.loc[
                        alert_attack_mask,
                        "label",
                    ]
                }
            )
        )

        return AlertBudgetResult(
            total_events=len(ranked),
            total_attacks=total_attacks,
            budget_fraction=budget_fraction,
            alert_count=alert_count,
            true_alerts=true_alerts,
            false_alerts=false_alerts,
            precision_at_budget=precision,
            attack_recall_at_budget=recall,
            false_positive_rate=false_positive_rate,
            attack_types_surfaced=surfaced,
        )


def demo_results() -> pd.DataFrame:
    """
    Small deterministic sanity dataset.

    This validates the ranking/evaluation logic only.
    The final benchmark should use SentinelAI's actual
    scored synthetic evaluation dataset.
    """

    rows: list[dict[str, object]] = []

    # 990 normal events.
    for index in range(990):
        rows.append(
            {
                "event_id": f"NORMAL_{index:04d}",
                "risk_score": float(index % 25),
                "label": "normal",
            }
        )

    attacks = [
        ("brute_force", 92.0),
        ("brute_force", 89.0),
        ("credential_stuffing", 88.0),
        ("credential_stuffing", 86.0),
        ("impossible_travel", 95.0),
        ("impossible_travel", 94.0),
        ("lateral_movement", 91.0),
        ("lateral_movement", 90.0),
        ("device_spoofing", 87.0),
        ("device_spoofing", 85.0),
    ]

    for index, (label, risk_score) in enumerate(
        attacks
    ):
        rows.append(
            {
                "event_id": f"ATTACK_{index:04d}",
                "risk_score": risk_score,
                "label": label,
            }
        )

    return pd.DataFrame(rows)


def main() -> None:
    results = demo_results()

    evaluator = AlertBudgetEvaluator()

    evaluation = evaluator.evaluate(
        results,
        budget_fraction=0.01,
    )

    print()
    print("=" * 58)
    print("       SENTINELAI ANALYST ALERT BUDGET")
    print("=" * 58)

    print()
    print("Dataset")
    print("-" * 58)
    print(
        f"Events evaluated:          "
        f"{evaluation.total_events}"
    )
    print(
        f"Attack events:             "
        f"{evaluation.total_attacks}"
    )
    print(
        f"Normal events:             "
        f"{evaluation.total_events - evaluation.total_attacks}"
    )

    print()
    print("Alert Budget")
    print("-" * 58)
    print(
        f"Budget:                    "
        f"{evaluation.budget_fraction:.1%}"
    )
    print(
        f"Alerts surfaced:           "
        f"{evaluation.alert_count}"
    )
    print(
        f"True attack alerts:        "
        f"{evaluation.true_alerts}"
    )
    print(
        f"False alerts:              "
        f"{evaluation.false_alerts}"
    )

    print()
    print("Metrics")
    print("-" * 58)
    print(
        f"Precision@1%:              "
        f"{evaluation.precision_at_budget:.3f}"
    )
    print(
        f"Attack Recall@1%:          "
        f"{evaluation.attack_recall_at_budget:.3f}"
    )
    print(
        f"False Positive Rate:       "
        f"{evaluation.false_positive_rate:.3%}"
    )

    print()
    print("Attack Types Surfaced")
    print("-" * 58)

    if evaluation.attack_types_surfaced:
        for attack_type in (
            evaluation.attack_types_surfaced
        ):
            print(f"  - {attack_type}")
    else:
        print("  None")

    print()
    print("=" * 58)


if __name__ == "__main__":
    main()