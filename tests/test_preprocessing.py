"""Unit tests for preprocessing and deduplication."""
import pytest
import pandas as pd
from datetime import datetime, timedelta

from src.preprocessing import deduplicate_alerts, map_severity_scores, compute_event_frequencies


def test_deduplication_flags_burst_events():
    base = datetime(2026, 10, 20, 10, 0, 0)
    data = [
        {"event_id": "E1", "timestamp": base, "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "event_type": "SSH_Scan"},
        {"event_id": "E2", "timestamp": base + timedelta(seconds=10), "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "event_type": "SSH_Scan"},
        {"event_id": "E3", "timestamp": base + timedelta(seconds=20), "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "event_type": "SSH_Scan"},
        {"event_id": "E4", "timestamp": base + timedelta(minutes=15), "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "event_type": "SSH_Scan"},
    ]
    df = pd.DataFrame(data)
    df_dedup, stats = deduplicate_alerts(df, window_seconds=300)

    assert stats["total_raw"] == 4
    assert stats["duplicates_flagged"] == 2
    assert df_dedup.loc[df_dedup["event_id"] == "E1", "is_duplicate"].values[0] == False
    assert df_dedup.loc[df_dedup["event_id"] == "E2", "is_duplicate"].values[0] == True
    assert df_dedup.loc[df_dedup["event_id"] == "E3", "is_duplicate"].values[0] == True
    assert df_dedup.loc[df_dedup["event_id"] == "E4", "is_duplicate"].values[0] == False


def test_severity_score_mapping():
    df = pd.DataFrame({"severity": ["low", "Medium", "HIGH", "CRITICAL", "unknown"]})
    df_mapped = map_severity_scores(df)

    assert df_mapped["severity_score"].iloc[0] == 25.0
    assert df_mapped["severity_score"].iloc[1] == 50.0
    assert df_mapped["severity_score"].iloc[2] == 75.0
    assert df_mapped["severity_score"].iloc[3] == 100.0
    assert df_mapped["severity_score"].iloc[4] == 25.0  # default fallback


def test_frequency_calculation():
    df = pd.DataFrame({
        "event_id": ["E1", "E2", "E3", "E4"],
        "source_ip": ["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.2"],
    })
    df_freq = compute_event_frequencies(df)
    assert "freq_score" in df_freq.columns
    assert df_freq["freq_score"].max() <= 100.0
    assert df_freq["freq_score"].min() >= 0.0
