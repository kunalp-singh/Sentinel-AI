import pandas as pd
import pytest

from sentinel.evaluation import AlertBudgetEvaluator


def test_top_one_percent_budget() -> None:
    rows: list[dict[str, object]] = []

    for index in range(99):
        rows.append(
            {
                "risk_score": float(index % 10),
                "label": "normal",
            }
        )

    rows.append(
        {
            "risk_score": 100.0,
            "label": "impossible_travel",
        }
    )

    result = AlertBudgetEvaluator().evaluate(
        pd.DataFrame(rows),
        budget_fraction=0.01,
    )

    assert result.total_events == 100
    assert result.alert_count == 1
    assert result.true_alerts == 1
    assert result.false_alerts == 0
    assert result.precision_at_budget == 1.0
    assert result.attack_recall_at_budget == 1.0


def test_false_alert_is_measured() -> None:
    rows = [
        {
            "risk_score": 100.0,
            "label": "normal",
        },
        {
            "risk_score": 90.0,
            "label": "brute_force",
        },
    ]

    for _ in range(98):
        rows.append(
            {
                "risk_score": 0.0,
                "label": "normal",
            }
        )

    result = AlertBudgetEvaluator().evaluate(
        pd.DataFrame(rows),
        budget_fraction=0.01,
    )

    assert result.alert_count == 1
    assert result.true_alerts == 0
    assert result.false_alerts == 1
    assert result.precision_at_budget == 0.0


def test_attack_types_are_reported() -> None:
    rows = [
        {
            "risk_score": 100.0,
            "label": "impossible_travel",
        },
        {
            "risk_score": 99.0,
            "label": "device_spoofing",
        },
    ]

    for _ in range(98):
        rows.append(
            {
                "risk_score": 0.0,
                "label": "normal",
            }
        )

    result = AlertBudgetEvaluator().evaluate(
        pd.DataFrame(rows),
        budget_fraction=0.02,
    )

    assert result.attack_types_surfaced == (
        "device_spoofing",
        "impossible_travel",
    )


def test_empty_results_are_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="empty result set",
    ):
        AlertBudgetEvaluator().evaluate(
            pd.DataFrame()
        )


@pytest.mark.parametrize(
    "budget",
    [
        0.0,
        -0.1,
        1.1,
    ],
)
def test_invalid_budget_is_rejected(
    budget: float,
) -> None:
    results = pd.DataFrame(
        [
            {
                "risk_score": 10.0,
                "label": "normal",
            }
        ]
    )

    with pytest.raises(
        ValueError,
        match="budget_fraction",
    ):
        AlertBudgetEvaluator().evaluate(
            results,
            budget_fraction=budget,
        )