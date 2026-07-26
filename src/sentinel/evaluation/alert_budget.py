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
    """Evaluate ranked risk scores under a fixed analyst budget."""

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

        precision = true_alerts / alert_count

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