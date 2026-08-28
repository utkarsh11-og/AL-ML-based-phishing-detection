"""
Model Training, Cross-Model Benchmarking, and Serialization Pipeline.

Trains and evaluates:
1. Logistic Regression (Linear baseline)
2. Decision Tree (Interpretable tree baseline)
3. Random Forest (Ensemble bagging)
4. Gradient Boosting (Ensemble boosting)

Evaluates on Accuracy, Precision, Recall, F1-Score, and ROC-AUC.
Serializes the best-performing model to ml/models/phishing_model_v1.joblib
and records benchmark metrics in ml/models/model_metadata.json.
"""

import os
import sys
import json
import logging
from typing import Dict, Any
import pandas as pd
import numpy as np
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def train_and_evaluate_all(
    train_path: str = "ml/datasets/processed/train_features.csv",
    test_path: str = "ml/datasets/processed/test_features.csv",
    models_dir: str = "ml/models"
) -> Dict[str, Any]:
    """
    Loads train/test feature matrices, trains 4 classifiers, evaluates all metrics,
    and serializes the champion model along with benchmark records.
    """
    os.makedirs(models_dir, exist_ok=True)

    # 1. Load Data
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    feature_cols = [c for c in train_df.columns if c != "label"]
    X_train, y_train = train_df[feature_cols], train_df["label"]
    X_test, y_test = test_df[feature_cols], test_df["label"]

    logger.info(f"Training on {X_train.shape[0]} samples with {X_train.shape[1]} features.")
    logger.info(f"Testing on {X_test.shape[0]} samples.")

    # 2. Define Model Candidates
    candidates = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Decision Tree": DecisionTreeClassifier(max_depth=6, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, random_state=42),
    }

    results = {}
    fitted_models = {}

    # 3. Train & Evaluate Each Candidate
    for name, model in candidates.items():
        logger.info(f"Training {name}...")
        model.fit(X_train, y_train)
        fitted_models[name] = model

        y_pred = model.predict(X_test)
        
        # Calculate probability for ROC-AUC
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test)[:, 1]
            auc = round(float(roc_auc_score(y_test, y_proba)), 4)
        else:
            auc = 0.0

        acc = round(float(accuracy_score(y_test, y_pred)), 4)
        prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
        rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
        f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
        cm = confusion_matrix(y_test, y_pred).tolist()

        results[name] = {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": auc,
            "confusion_matrix": cm,
        }

    # 4. Create Comparison DataFrame & Print Summary
    comparison_df = pd.DataFrame(results).T.sort_values(by=["f1_score", "recall"], ascending=False)
    print("\n=============================================")
    print("        MODEL BENCHMARK COMPARISON          ")
    print("=============================================")
    print(comparison_df[["accuracy", "precision", "recall", "f1_score", "roc_auc"]])
    print("=============================================\n")

    # 5. Select Best Model (Prioritizing F1-Score, then Recall, with Random Forest preference on ties)
    if "Random Forest" in comparison_df.index and comparison_df.loc["Random Forest", "f1_score"] == comparison_df["f1_score"].max():
        best_model_name = "Random Forest"
    else:
        best_model_name = comparison_df.index[0]
        
    best_model = fitted_models[best_model_name]
    logger.info(f"Champion Model Selected: '{best_model_name}' (F1: {results[best_model_name]['f1_score']:.4f}, Recall: {results[best_model_name]['recall']:.4f})")

    # 6. Extract Feature Importances (if available)
    feature_importances = {}
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        feature_importances = {
            col: round(float(imp), 4)
            for col, imp in sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
        }
    elif hasattr(best_model, "coef_"):
        coefs = np.abs(best_model.coef_[0])
        feature_importances = {
            col: round(float(c), 4)
            for col, c in sorted(zip(feature_cols, coefs), key=lambda x: x[1], reverse=True)
        }

    # 7. Save Champion Model Artifact
    model_save_path = os.path.join(models_dir, "phishing_model_v1.joblib")
    joblib.dump(
        {
            "model": best_model,
            "model_name": best_model_name,
            "feature_names": feature_cols,
            "version": "1.0.0"
        },
        model_save_path
    )
    logger.info(f"Model artifact serialized to {model_save_path}")

    # 8. Save Metadata & Comparison Records
    metadata = {
        "champion_model": best_model_name,
        "version": "1.0.0",
        "feature_names": feature_cols,
        "feature_count": len(feature_cols),
        "test_metrics": results[best_model_name],
        "all_model_results": results,
        "feature_importances": feature_importances,
    }

    metadata_path = os.path.join(models_dir, "model_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    
    comparison_csv_path = os.path.join(models_dir, "model_comparison.csv")
    comparison_df.to_csv(comparison_csv_path)

    logger.info(f"Model metadata & comparison records saved to {metadata_path}")
    return metadata


if __name__ == "__main__":
    train_and_evaluate_all()
