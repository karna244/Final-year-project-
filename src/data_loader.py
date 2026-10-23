"""Data loader module for ingesting cybersecurity alert logs."""
import os
import pandas as pd
from typing import Dict, Any, Tuple


REQUIRED_COLUMNS = [
    "event_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "event_type",
    "severity",
]

DEFAULT_FALLBACKS = {
    "source_port": 0,
    "destination_port": 0,
    "protocol": "TCP",
    "asset_criticality": "Tier-3_Workstation",
    "process_name": "unknown",
    "user": "unknown",
    "label": 0,
}


def load_alerts(file_path: str) -> pd.DataFrame:
    """
    Load security alerts from a CSV file and validate schema.
    
    Args:
        file_path: Path to raw or preprocessed alerts CSV.
        
    Returns:
        Validated pandas DataFrame with standardized types.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Alert dataset not found at path: {file_path}")

    df = pd.read_csv(file_path)

    # Check for core required columns
    missing_core = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_core:
        raise ValueError(
            f"Dataset is missing essential columns: {missing_core}. "
            f"Required: {REQUIRED_COLUMNS}"
        )

    # Fill optional missing columns with standardized fallbacks
    for col, default_val in DEFAULT_FALLBACKS.items():
        if col not in df.columns:
            df[col] = default_val
        else:
            df[col] = df[col].fillna(default_val)

    # Parse and standardize timestamps
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if df["timestamp"].isna().any():
        # Fallback forward fill for unparseable dates
        df["timestamp"] = df["timestamp"].ffill().bfill()

    # Sort chronologically
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Normalize string columns
    str_cols = ["source_ip", "destination_ip", "protocol", "event_type", "severity", "process_name", "user"]
    for sc in str_cols:
        df[sc] = df[sc].astype(str).str.strip()

    return df


def get_dataset_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """Return key metrics and health summary of loaded alerts."""
    return {
        "total_alerts": len(df),
        "unique_sources": df["source_ip"].nunique(),
        "unique_destinations": df["destination_ip"].nunique(),
        "time_start": str(df["timestamp"].min()),
        "time_end": str(df["timestamp"].max()),
        "event_types_count": df["event_type"].nunique(),
        "severity_distribution": df["severity"].value_counts().to_dict(),
        "has_labels": "label" in df.columns and not df["label"].isna().all(),
        "malicious_count": int((df["label"] == 1).sum()) if "label" in df.columns else 0,
        "benign_count": int((df["label"] == 0).sum()) if "label" in df.columns else 0,
    }
