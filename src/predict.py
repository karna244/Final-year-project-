"""Inference module for scoring and prioritizing incoming security alerts."""
import os
import joblib
import pandas as pd
import numpy as np
from typing import Tuple

from src.features import prepare_feature_matrix
from src.risk_scoring import calculate_risk_scores


def predict_alerts(
    df: pd.DataFrame,
    model_path: str = "models/random_forest_model.joblib",
    preprocessor_path: str = "models/preprocessor.joblib",
    weights: dict = None,
    thresholds: dict = None,
) -> pd.DataFrame:
    """
    Run inference on incoming alerts using saved model and scoring engine.
    """
    if not os.path.exists(model_path) or not os.path.exists(preprocessor_path):
        raise FileNotFoundError("Trained model or preprocessor artifact missing. Run training first.")

    model = joblib.load(model_path)
    preprocessor = joblib.load(preprocessor_path)

    df_out = df.copy()

    # Prepare feature matrix
    X_input, _ = prepare_feature_matrix(df_out, preprocessor=preprocessor, fit=False)

    # Model inference
    predictions = model.predict(X_input)
    probabilities = model.predict_proba(X_input)[:, 1]

    df_out["predicted_class"] = predictions
    df_out["ml_prob"] = np.round(probabilities, 4)

    # Compute risk scores & priorities
    df_out = calculate_risk_scores(df_out, weights=weights, thresholds=thresholds)

    return df_out
