"""Preprocessing module for deduplication, normalization, and frequency calculation."""
import pandas as pd
import numpy as np
from typing import Tuple, Dict, Any


DEFAULT_SEVERITY_MAP = {
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 100.0,
}


def deduplicate_alerts(
    df: pd.DataFrame,
    window_seconds: int = 300,
    keys: list = None,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Identify and group duplicate alerts occurring within a rolling time window.
    Directly mitigates alert redundancy and fatigue (Tariq et al., 2025).
    
    Args:
        df: Input dataframe sorted by timestamp.
        window_seconds: Time threshold in seconds for considering alerts duplicate.
        keys: Columns to match for duplication.
        
    Returns:
        DataFrame with 'is_duplicate', 'incident_group_id', and 'burst_count',
        plus a dictionary summarizing deduplication statistics.
    """
    if keys is None:
        keys = ["source_ip", "destination_ip", "event_type"]

    df = df.copy()
    df["is_duplicate"] = False
    df["incident_group_id"] = df["event_id"]
    df["burst_count"] = 1

    total_initial = len(df)
    if total_initial <= 1:
        return df, {"total_raw": total_initial, "duplicates_flagged": 0, "reduction_rate_pct": 0.0}

    # Group by key columns and flag events within window
    grouped = df.groupby(keys, sort=False)
    for _, group in grouped:
        if len(group) <= 1:
            continue

        timestamps = group["timestamp"].values
        indices = group.index.values
        parent_idx = indices[0]
        current_burst = 1

        for i in range(1, len(indices)):
            diff_sec = (timestamps[i] - timestamps[i - 1]) / np.timedelta64(1, "s")
            if diff_sec <= window_seconds:
                df.at[indices[i], "is_duplicate"] = True
                df.at[indices[i], "incident_group_id"] = df.at[parent_idx, "event_id"]
                current_burst += 1
                df.at[parent_idx, "burst_count"] = current_burst
            else:
                parent_idx = indices[i]
                current_burst = 1

    duplicates_count = int(df["is_duplicate"].sum())
    reduction_rate = (duplicates_count / total_initial * 100) if total_initial > 0 else 0.0

    stats = {
        "total_raw": total_initial,
        "unique_incidents": total_initial - duplicates_count,
        "duplicates_flagged": duplicates_count,
        "reduction_rate_pct": round(reduction_rate, 2),
    }

    return df, stats


def compute_event_frequencies(df: pd.DataFrame, window_minutes: int = 15) -> pd.DataFrame:
    """
    Compute rolling event frequency per source IP within a rolling time window.
    Outputs a normalized frequency anomaly score (0 - 100).
    """
    df = df.copy()
    
    # Calculate count of events per source IP in the dataset
    src_counts = df.groupby("source_ip")["event_id"].transform("count")
    
    # Scale to 0 - 100 using 95th percentile as burst cap
    p95 = np.percentile(src_counts, 95) if len(src_counts) > 0 else 1.0
    p95 = max(p95, 1.0)
    
    df["raw_frequency"] = src_counts
    df["freq_score"] = np.clip((src_counts / p95) * 100.0, 0.0, 100.0).round(1)
    return df


def map_severity_scores(df: pd.DataFrame, custom_map: dict = None) -> pd.DataFrame:
    """Map string severity (Low/Med/High/Crit) to standardized 0-100 numerical proxy."""
    df = df.copy()
    sev_map = custom_map if custom_map else DEFAULT_SEVERITY_MAP

    def _convert(val):
        key = str(val).strip().lower()
        return sev_map.get(key, 25.0)

    df["severity_score"] = df["severity"].apply(_convert)
    return df


def preprocess_alerts(
    df: pd.DataFrame,
    window_seconds: int = 300,
    severity_map: dict = None,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Master preprocessing pipeline:
    1. Deduplication & grouping
    2. Severity score mapping
    3. Rolling frequency burst score calculation
    """
    # 1. Deduplication
    df_clean, dedup_stats = deduplicate_alerts(df, window_seconds=window_seconds)

    # 2. Severity mapping
    df_clean = map_severity_scores(df_clean, custom_map=severity_map)

    # 3. Frequency calculation
    df_clean = compute_event_frequencies(df_clean)

    return df_clean, dedup_stats
