"""Hybrid risk scoring engine and explainable reason code generator."""
import pandas as pd
import numpy as np
from typing import Dict, Any, List


DEFAULT_WEIGHTS = {
    "ml_prob_weight": 0.40,
    "severity_weight": 0.25,
    "context_weight": 0.20,
    "frequency_weight": 0.15,
}

DEFAULT_THRESHOLDS = {
    "critical": 80.0,
    "high": 60.0,
    "medium": 30.0,
    "low": 0.0,
}


def generate_reason_codes(row: pd.Series) -> List[str]:
    """
    Generate transparent, human-interpretable reason codes for an alert.
    Supports Human-AI Teaming and Tier-1 SOC analyst decision-making.
    """
    reasons = []

    ml_p = row.get("ml_prob", 0.0)
    sev_s = row.get("severity_score", 0.0)
    ctx_s = row.get("context_score", 0.0)
    frq_s = row.get("freq_score", 0.0)
    is_dup = row.get("is_duplicate", False)
    is_hub = row.get("is_hub_incident", False)

    if is_dup:
        reasons.append("RC-SUPPRESSED (Burst Duplicate)")

    if ml_p >= 0.70:
        reasons.append(f"RC-ML-ANOMALY ({int(ml_p*100)}% Malicious Confidence)")
    elif ml_p <= 0.15:
        reasons.append("RC-ML-BENIGN (High Benign Confidence)")

    if sev_s >= 75.0:
        reasons.append(f"RC-SEV-ELEVATED ({row.get('severity', 'High')})")

    if is_hub or ctx_s >= 60.0:
        reasons.append("RC-GRAPH-HUB (High-Connectivity Network Entity)")

    if frq_s >= 65.0:
        reasons.append("RC-FREQ-BURST (Anomalous Event Velocity)")

    if not reasons:
        reasons.append("RC-BASELINE-MONITORING (Standard Telemetry)")

    return reasons


def calculate_risk_scores(
    df: pd.DataFrame,
    weights: dict = None,
    thresholds: dict = None,
) -> pd.DataFrame:
    """
    Calculate unified incident risk score:
    R = w1 * (ml_prob * 100) + w2 * severity_score + w3 * context_score + w4 * freq_score
    Bounded strictly in [0, 100].
    """
    df = df.copy()
    w = weights if weights else DEFAULT_WEIGHTS
    th = thresholds if thresholds else DEFAULT_THRESHOLDS

    # Component values (all normalized to 0 - 100)
    M = (df["ml_prob"] * 100.0) if "ml_prob" in df.columns else np.zeros(len(df))
    S = df["severity_score"] if "severity_score" in df.columns else np.full(len(df), 25.0)
    C = df["context_score"] if "context_score" in df.columns else np.zeros(len(df))
    F = df["freq_score"] if "freq_score" in df.columns else np.zeros(len(df))

    # Weight factors
    w1 = w.get("ml_prob_weight", 0.40)
    w2 = w.get("severity_weight", 0.25)
    w3 = w.get("context_weight", 0.20)
    w4 = w.get("frequency_weight", 0.15)

    # Calculate unified risk score
    raw_risk = (w1 * M) + (w2 * S) + (w3 * C) + (w4 * F)
    df["risk_score"] = np.clip(raw_risk, 0.0, 100.0).round(1)

    # Classify Priority Levels
    crit_th = th.get("critical", 80.0)
    high_th = th.get("high", 60.0)
    med_th = th.get("medium", 30.0)

    conditions = [
        df["risk_score"] >= crit_th,
        df["risk_score"] >= high_th,
        df["risk_score"] >= med_th,
    ]
    choices = ["Critical", "High", "Medium"]
    df["priority"] = np.select(conditions, choices, default="Low")

    # Priority Color Mapping
    color_map = {
        "Critical": "#E63946", # Crimson Red
        "High": "#F4A261",     # Deep Amber
        "Medium": "#E9C46A",   # Warm Yellow
        "Low": "#2A9D8F",      # Teal Green
    }
    df["priority_color"] = df["priority"].map(color_map)

    # Generate Explainability Reason Codes
    df["reason_codes"] = [generate_reason_codes(row) for _, row in df.iterrows()]

    return df
