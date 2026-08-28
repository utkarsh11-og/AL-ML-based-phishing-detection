"""
Security Risk Engine & Prevention Policy Layer.

Decouples raw ML probability from final security verdicts.
Calculates a calibrated 0-100 Risk Score and determines actionable prevention responses
(ALLOW, WARN, STRONG_WARNING, BLOCK).
"""

import os
import sys
import logging
from typing import Dict, Any, Optional
import pandas as pd
import joblib

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.features.url_features import URLFeatureExtractor
from src.explainer import FeatureExplainer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Combines ML model predictions, statistical confidence, and heuristic security rules
    into a calibrated 0-100 Risk Score and actionable prevention policy.
    """

    # Configurable Risk Thresholds
    THRESHOLD_LOW = 30       # 0 - 29: LOW
    THRESHOLD_MEDIUM = 60    # 30 - 59: MEDIUM
    THRESHOLD_HIGH = 80      # 60 - 79: HIGH
    # 80 - 100: CRITICAL

    def __init__(self, model_path: str = "ml/models/phishing_model_v1.joblib"):
        self.extractor = URLFeatureExtractor()
        self.explainer = FeatureExplainer()
        self.model_path = model_path
        self.model_bundle = self._load_model()

    def _load_model(self) -> Optional[Dict[str, Any]]:
        """Loads serialized model artifact."""
        if not os.path.exists(self.model_path):
            logger.warning(f"Model artifact not found at {self.model_path}. Running in heuristic fallback mode.")
            return None
        try:
            bundle = joblib.load(self.model_path)
            logger.info(f"Loaded ML model: {bundle.get('model_name', 'Unknown')} v{bundle.get('version', '1.0')}")
            return bundle
        except Exception as e:
            logger.error(f"Failed to load model from {self.model_path}: {e}")
            return None

    def calculate_risk_score(self, ml_prob: float, features: Dict[str, Any]) -> int:
        """
        Synthesizes raw ML probability (0.0 - 1.0) with heuristic modifiers into 0 - 100 integer.
        """
        # Baseline score directly derived from ML model confidence
        base_score = ml_prob * 100.0

        # Heuristic Modifiers (Defense in Depth)
        modifier = 0.0

        # Hard Red Flag: IP address as hostname (+35)
        if features.get("has_ip_address", 0) == 1:
            modifier += 35.0

        # Hard Red Flag: '@' symbol in URL (+35)
        if features.get("num_at_symbols", 0) > 0:
            modifier += 35.0

        # Double slash redirect (+20)
        if features.get("has_double_slash_redirect", 0) == 1:
            modifier += 20.0

        # Deep subdomain nesting (+15 for >= 3 levels)
        if features.get("num_subdomains", 0) >= 3:
            modifier += 15.0

        # Multiple sensitive keywords (+15)
        if features.get("keyword_count", 0) >= 2:
            modifier += 15.0

        # High entropy (> 4.5) (+15)
        if features.get("url_entropy", 0.0) > 4.5:
            modifier += 15.0

        # Combine and clamp to [0, 100]
        final_score = int(round(min(100.0, max(0.0, (base_score * 0.6) + (modifier * 0.4)))))
        
        # Unequivocal critical indicators: @ symbol or raw IP with sensitive keywords
        if features.get("num_at_symbols", 0) > 0 or (features.get("has_ip_address", 0) == 1 and features.get("keyword_count", 0) > 0):
            final_score = max(final_score, 85)

        # If ML probability is extremely high (>0.85), ensure score is at least 80
        if ml_prob >= 0.85:
            final_score = max(final_score, 85)
        # If ML probability is very low (<0.10) and no hard red flags, ensure score is < 30
        elif ml_prob <= 0.10 and features.get("has_ip_address", 0) == 0 and features.get("num_at_symbols", 0) == 0:
            final_score = min(final_score, 25)

        return final_score

    def determine_policy_action(self, risk_score: int) -> Dict[str, str]:
        """
        Translates a numeric risk score into a prevention action and risk category.
        """
        if risk_score < self.THRESHOLD_LOW:
            return {
                "risk_level": "low",
                "action": "ALLOW",
                "recommendation": "Safe to access. URL exhibits standard lexical structure and trusted indicators."
            }
        elif risk_score < self.THRESHOLD_MEDIUM:
            return {
                "risk_level": "medium",
                "action": "WARN",
                "recommendation": "Exercise caution. Suspicious structural or lexical anomalies detected."
            }
        elif risk_score < self.THRESHOLD_HIGH:
            return {
                "risk_level": "high",
                "action": "STRONG_WARNING",
                "recommendation": "High risk of phishing. Do not submit sensitive passwords, MFA tokens, or credit cards."
            }
        else:
            return {
                "risk_level": "critical",
                "action": "BLOCK",
                "recommendation": "Critical threat detected. Connection should be blocked to prevent credential theft."
            }

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Full end-to-end analysis of a URL string:
        Extracts features -> Evaluates ML Model -> Computes Risk Score -> Assigns Action -> Generates Reasons.
        """
        # 1. Feature Extraction
        features = self.extractor.extract_features(url)

        # 2. ML Model Inference
        ml_prob = 0.5  # Fallback default
        model_version = "heuristic_fallback"
        model_name = "HeuristicEngine"

        if self.model_bundle:
            model = self.model_bundle["model"]
            model_name = self.model_bundle.get("model_name", "Random Forest")
            model_version = self.model_bundle.get("version", "1.0.0")
            feature_names = self.model_bundle["feature_names"]

            # Construct DataFrame with matching feature order
            df_features = pd.DataFrame([[features[col] for col in feature_names]], columns=feature_names)
            
            if hasattr(model, "predict_proba"):
                ml_prob = float(model.predict_proba(df_features)[0, 1])
            else:
                ml_prob = float(model.predict(df_features)[0])

        # 3. Risk Engine Scoring
        risk_score = self.calculate_risk_score(ml_prob, features)
        policy = self.determine_policy_action(risk_score)

        # 4. Explainability Attribution
        reasons = self.explainer.explain_url_features(features)

        # 5. Build Final Response
        return {
            "url": url,
            "classification": "phishing" if risk_score >= self.THRESHOLD_MEDIUM else "legitimate",
            "risk_score": risk_score,
            "risk_level": policy["risk_level"],
            "action": policy["action"],
            "recommendation": policy["recommendation"],
            "model_confidence": round(ml_prob, 4),
            "model_name": model_name,
            "model_version": model_version,
            "reasons": reasons,
            "features": features,
        }


if __name__ == "__main__":
    engine = RiskEngine()
    
    test_urls = [
        "https://www.google.com/search?q=cybersecurity+defense",
        "http://paypal.com@secure-verify-account.xyz/login.php",
        "http://192.168.1.100/chase-bank/update.html",
    ]

    for u in test_urls:
        res = engine.analyze_url(u)
        print("\n" + "="*60)
        print(f"URL: {res['url']}")
        print(f"Classification : {res['classification'].upper()} | Action: {res['action']}")
        print(f"Risk Score     : {res['risk_score']}/100 ({res['risk_level'].upper()})")
        print(f"ML Confidence  : {res['model_confidence']:.2%}")
        print("Reasons:")
        for r in res["reasons"]:
            print(f"  [{r['severity'].upper()}] {r['title']}: {r['description']}")
