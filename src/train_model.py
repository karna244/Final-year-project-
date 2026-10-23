"""Model training and evaluation module using Scikit-Learn Random Forest."""
import os
import json
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_auc_score,
    classification_report,
)
from typing import Dict, Any, Tuple

from src.features import prepare_feature_matrix


def train_and_evaluate(
    df: pd.DataFrame,
    test_size: float = 0.25,
    random_state: int = 42,
    model_save_path: str = "models/random_forest_model.joblib",
    preprocessor_save_path: str = "models/preprocessor.joblib",
    report_save_path: str = "reports/metrics_summary.json",
    plot_save_path: str = "reports/confusion_matrix.png",
) -> Tuple[RandomForestClassifier, Any, Dict[str, Any]]:
    """
    Train Random Forest classifier on labeled alert data and evaluate on held-out test set.
    Strictly prevents data leakage by fitting preprocessor only on training data.
    """
    if "label" not in df.columns:
        raise ValueError("Cannot train model: 'label' column not found in dataset.")

    y = df["label"].astype(int).values

    # Train / Test split
    df_train, df_test, y_train, y_test = train_test_split(
        df, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Fit preprocessor on training set only
    X_train, preprocessor = prepare_feature_matrix(df_train, fit=True)
    # Transform test set using fitted preprocessor
    X_test, _ = prepare_feature_matrix(df_test, preprocessor=preprocessor, fit=False)

    # Train Random Forest Classifier
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Predictions & probabilities on held-out test set
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    # Calculate rigorous metrics
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    auc = float(roc_auc_score(y_test, y_prob)) if len(np.unique(y_test)) > 1 else 1.0

    metrics = {
        "train_samples": len(df_train),
        "test_samples": len(df_test),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "roc_auc": round(auc, 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
    }

    # Save artifacts
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    joblib.dump(clf, model_save_path)
    joblib.dump(preprocessor, preprocessor_save_path)

    os.makedirs(os.path.dirname(report_save_path), exist_ok=True)
    with open(report_save_path, "w") as f:
        json.dump(metrics, f, indent=2)

    # Generate and save confusion matrix figure
    fig, ax = plt.subplots(figsize=(5, 4))
    disp = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=["Benign (0)", "Attack (1)"],
    )
    disp.plot(cmap="Blues", ax=ax, colorbar=False)
    ax.set_title(f"Confusion Matrix (Test FPR: {round(fpr*100, 2)}%)")
    plt.tight_layout()
    plt.savefig(plot_save_path, dpi=200)
    plt.close()

    return clf, preprocessor, metrics
