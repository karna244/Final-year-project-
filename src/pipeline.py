"""Unified end-to-end orchestration pipeline for cyber incident triage."""
import os
import yaml
import pandas as pd
import networkx as nx
from typing import Tuple, Dict, Any

from src.data_loader import load_alerts
from src.preprocessing import preprocess_alerts
from src.graph_analysis import compute_graph_features
from src.train_model import train_and_evaluate
from src.predict import predict_alerts


def load_config(config_path: str = "config/settings.yaml") -> Dict[str, Any]:
    """Load system configuration from YAML file."""
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return {}


def run_full_pipeline(
    raw_data_path: str = "data/raw/cybersecurity_alerts.csv",
    config_path: str = "config/settings.yaml",
    retrain: bool = True,
) -> Tuple[pd.DataFrame, nx.DiGraph, Dict[str, Any]]:
    """
    Execute complete end-to-end triage pipeline:
    1. Load data
    2. Preprocess & Deduplicate
    3. Build NetworkX Entity Graph & Context
    4. Train / Load ML Classifier
    5. Calculate Multi-Factor Risk & Priorities
    """
    config = load_config(config_path)
    weights = config.get("risk_weights")
    thresholds = config.get("priority_thresholds")
    sev_map = config.get("severity_mapping")

    # Step 1: Load raw alerts
    df_raw = load_alerts(raw_data_path)

    # Step 2: Preprocess & Deduplicate
    df_prep, dedup_stats = preprocess_alerts(df_raw, severity_map=sev_map)

    # Step 3: NetworkX Graph Context
    df_graph, G, graph_stats = compute_graph_features(df_prep)

    # Step 4: ML Training or Inference
    model_path = config.get("paths", {}).get("model_save", "models/random_forest_model.joblib")
    preproc_path = config.get("paths", {}).get("preprocessor_save", "models/preprocessor.joblib")

    if retrain or not os.path.exists(model_path):
        _, _, ml_metrics = train_and_evaluate(
            df_graph,
            model_save_path=model_path,
            preprocessor_save_path=preproc_path,
        )
    else:
        ml_metrics = {}

    # Step 5: Scoring and Prediction
    df_triaged = predict_alerts(
        df_graph,
        model_path=model_path,
        preprocessor_path=preproc_path,
        weights=weights,
        thresholds=thresholds,
    )

    # Save processed results
    processed_save = config.get("paths", {}).get("processed_data", "data/processed/alerts_processed.csv")
    os.makedirs(os.path.dirname(processed_save), exist_ok=True)
    df_triaged.to_csv(processed_save, index=False)

    summary = {
        "dedup_stats": dedup_stats,
        "graph_stats": graph_stats,
        "ml_metrics": ml_metrics,
        "total_triaged": len(df_triaged),
        "priority_counts": df_triaged["priority"].value_counts().to_dict(),
    }

    return df_triaged, G, summary
