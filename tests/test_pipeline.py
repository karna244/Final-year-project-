"""Integration tests for the end-to-end triage pipeline."""
import os
import pytest
from src.pipeline import run_full_pipeline


def test_full_pipeline_execution():
    raw_path = "data/raw/cybersecurity_alerts.csv"
    assert os.path.exists(raw_path), f"Missing raw alerts dataset at {raw_path}"

    df_triaged, G, summary = run_full_pipeline(
        raw_data_path=raw_path,
        config_path="config/settings.yaml",
        retrain=True,
    )

    # Assertions
    assert len(df_triaged) > 0
    assert "risk_score" in df_triaged.columns
    assert "priority" in df_triaged.columns
    assert "reason_codes" in df_triaged.columns
    assert "ml_prob" in df_triaged.columns

    # Check graph
    assert G.number_of_nodes() > 0
    assert G.number_of_edges() > 0

    # Check metrics
    assert "ml_metrics" in summary
    assert "accuracy" in summary["ml_metrics"]
    assert summary["ml_metrics"]["accuracy"] > 0.80  # Realistic threshold
