"""Feature engineering module for machine learning input preparation."""
import pandas as pd
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from typing import Tuple, List


NUMERICAL_FEATURES = [
    "destination_port",
    "hour_of_day",
    "day_of_week",
    "graph_degree",
    "raw_frequency",
]

CATEGORICAL_FEATURES = [
    "protocol",
    "event_type",
    "asset_criticality",
]


def extract_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract hour and day of week from timestamp."""
    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    
    df["hour_of_day"] = df["timestamp"].dt.hour.fillna(12).astype(int)
    df["day_of_week"] = df["timestamp"].dt.dayofweek.fillna(0).astype(int)
    return df


def build_preprocessor() -> ColumnTransformer:
    """Construct Scikit-learn ColumnTransformer for ML features."""
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "num",
                StandardScaler(),
                NUMERICAL_FEATURES,
            ),
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                CATEGORICAL_FEATURES,
            ),
        ]
    )
    return preprocessor


def prepare_feature_matrix(
    df: pd.DataFrame,
    preprocessor: ColumnTransformer = None,
    fit: bool = False,
) -> Tuple[np.ndarray, ColumnTransformer]:
    """
    Extract features and transform into numerical matrix for Random Forest.
    
    Args:
        df: Input DataFrame with raw/preprocessed columns.
        preprocessor: Fitted or unfitted ColumnTransformer.
        fit: Whether to fit preprocessor on this data (True for training, False for inference).
        
    Returns:
        Feature matrix X, and the fitted preprocessor.
    """
    df_feat = extract_temporal_features(df)

    # Ensure required columns exist
    for col in NUMERICAL_FEATURES:
        if col not in df_feat.columns:
            df_feat[col] = 0.0

    for col in CATEGORICAL_FEATURES:
        if col not in df_feat.columns:
            df_feat[col] = "unknown"

    X_subset = df_feat[NUMERICAL_FEATURES + CATEGORICAL_FEATURES]

    if preprocessor is None:
        preprocessor = build_preprocessor()

    if fit:
        X_trans = preprocessor.fit_transform(X_subset)
    else:
        X_trans = preprocessor.transform(X_subset)

    return X_trans, preprocessor
