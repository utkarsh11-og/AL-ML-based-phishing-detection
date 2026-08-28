"""
Unit tests for Machine Learning model loading and inference.
"""

import os
import pytest
import joblib
import pandas as pd
from ml.features.url_features import URLFeatureExtractor


def test_model_artifact_exists():
    model_path = "ml/models/phishing_model_v1.joblib"
    assert os.path.exists(model_path), "Trained model artifact should exist."


def test_model_inference_pipeline():
    model_path = "ml/models/phishing_model_v1.joblib"
    bundle = joblib.load(model_path)
    
    assert "model" in bundle
    assert "feature_names" in bundle
    assert len(bundle["feature_names"]) == 22

    model = bundle["model"]
    feature_names = bundle["feature_names"]

    extractor = URLFeatureExtractor()
    features = extractor.extract_features("http://paypa1-security-update.com/login.php")
    
    df_features = pd.DataFrame([[features[col] for col in feature_names]], columns=feature_names)
    
    pred = model.predict(df_features)[0]
    prob = model.predict_proba(df_features)[0, 1]

    assert pred in [0, 1]
    assert 0.0 <= prob <= 1.0
