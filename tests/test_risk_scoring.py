"""Unit tests for hybrid risk scoring and priority categorization."""
import pytest
import pandas as pd
from src.risk_scoring import calculate_risk_scores, generate_reason_codes


def test_risk_scores_strictly_bounded_0_to_100():
    df = pd.DataFrame({
        "event_id": ["E1", "E2", "E3"],
        "ml_prob": [1.0, 0.0, 0.5],
        "severity_score": [100.0, 0.0, 50.0],
        "context_score": [100.0, 0.0, 50.0],
        "freq_score": [100.0, 0.0, 50.0],
        "is_duplicate": [False, False, False],
        "is_hub_incident": [True, False, False],
        "severity": ["Critical", "Low", "Medium"],
    })
    scored = calculate_risk_scores(df)

    assert scored["risk_score"].iloc[0] == 100.0
    assert scored["priority"].iloc[0] == "Critical"

    assert scored["risk_score"].iloc[1] == 0.0
    assert scored["priority"].iloc[1] == "Low"

    assert 40.0 <= scored["risk_score"].iloc[2] <= 60.0
    assert scored["priority"].iloc[2] in ["Medium", "High"]


def test_reason_codes_generation():
    row = pd.Series({
        "ml_prob": 0.85,
        "severity_score": 100.0,
        "context_score": 80.0,
        "freq_score": 90.0,
        "is_duplicate": True,
        "is_hub_incident": True,
        "severity": "Critical",
    })
    reasons = generate_reason_codes(row)
    assert any("RC-ML-ANOMALY" in r for r in reasons)
    assert any("RC-SUPPRESSED" in r for r in reasons)
    assert any("RC-GRAPH-HUB" in r for r in reasons)
