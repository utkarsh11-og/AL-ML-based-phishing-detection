"""
FastAPI REST Service for AI/ML Phishing Detection & Prevention Platform.

Provides high-performance endpoints for:
- Static & Machine Learning URL Risk Analysis
- Social Engineering & Email Threat Detection
- Model Performance Benchmarks & Explainability Insights
- Real-time Telemetry & Scan History
"""

import os
import sys
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, List, Any
import logging

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.app.schemas import (
    URLAnalysisRequest, URLAnalysisResponse,
    EmailAnalysisRequest, EmailAnalysisResponse,
    HealthResponse, StatsResponse
)
from src.risk_engine import RiskEngine
from src.email_analyzer import EmailPhishingAnalyzer
from src.storage import StorageManager
from ml.datasets.fetch_realtime_data import run_realtime_pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("phishing_api")

app = FastAPI(
    title="NEXORA — AI/ML Phishing Detection & Prevention Platform",
    description="Enterprise-grade cybersecurity intelligence and autonomous threat mitigation platform engineered by Team NEXORA.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for Frontend Access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Security Engines & Persistent Storage
storage = StorageManager()
risk_engine = RiskEngine()
email_analyzer = EmailPhishingAnalyzer(risk_engine=risk_engine)


@app.get("/api/v1/health", response_model=HealthResponse, tags=["System Health"])
def get_system_health():
    """Returns real-time service health, model runtime status, and active engine version."""
    model_loaded = risk_engine.model_bundle is not None
    return {
        "status": "healthy" if model_loaded else "degraded",
        "service": "AI/ML Phishing Detection Engine",
        "model_loaded": model_loaded,
        "model_name": risk_engine.model_bundle.get("model_name", "None") if model_loaded else "None",
        "model_version": risk_engine.model_bundle.get("version", "None") if model_loaded else "None"
    }


@app.get("/api/v1/model/info", tags=["Machine Learning"])
def get_model_information():
    """Retrieves champion model metadata, evaluation metrics, and feature importances."""
    meta_path = "ml/models/model_metadata.json"
    if not os.path.exists(meta_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model metadata file not found. Ensure models have been trained."
        )
    with open(meta_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@app.post("/api/v1/dataset/refresh", tags=["Machine Learning"])
def refresh_realtime_threat_feeds():
    """Pulls live real-time threat intelligence feeds, re-extracts features, and retrains all models."""
    global risk_engine, email_analyzer
    try:
        run_realtime_pipeline()
        # Reload newly trained model into memory
        risk_engine = RiskEngine()
        email_analyzer = EmailPhishingAnalyzer(risk_engine=risk_engine)
        return {
            "status": "success",
            "message": "Real-time threat feeds fetched and champion ML models retrained successfully."
        }
    except Exception as e:
        logger.error(f"Failed to refresh real-time feeds: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Feed refresh error: {str(e)}"
        )


@app.post("/api/v1/extension/launch", tags=["Extension Integration"])
def launch_extension_in_browser():
    """Launches the user's browser with the NEXORA extension loaded automatically."""
    import subprocess
    ext_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../extension"))
    dash_url = "http://127.0.0.1:8000/dashboard/"
    
    try:
        # Try Chrome
        cmd = f'start "" chrome.exe --load-extension="{ext_path}" "{dash_url}"'
        subprocess.Popen(cmd, shell=True)
        return {"status": "success", "message": "Browser launched with NEXORA extension loaded automatically."}
    except Exception as e:
        try:
            # Fallback to Edge
            cmd = f'start "" msedge.exe --load-extension="{ext_path}" "{dash_url}"'
            subprocess.Popen(cmd, shell=True)
            return {"status": "success", "message": "Edge launched with NEXORA extension loaded."}
        except Exception as err:
            return {"status": "error", "message": f"Could not launch browser automatically: {err}"}


@app.get("/api/v1/stats", response_model=StatsResponse, tags=["Telemetry"])
def get_scan_statistics():
    """Returns aggregated real-time scan volume, threat detection ratio, and average risk score."""
    return storage.get_stats()


@app.get("/api/v1/history", tags=["Telemetry"])
def get_scan_history(limit: int = 50):
    """Returns real-time persistent scan history ordered by timestamp descending."""
    return storage.get_recent_scans(limit=limit)


@app.post("/api/v1/analyze/url", response_model=URLAnalysisResponse, tags=["Threat Analysis"])
def analyze_url_endpoint(payload: URLAnalysisRequest):
    """
    Performs static feature extraction, ML inference, and risk scoring on an untrusted URL.
    Returns calibrated 0-100 risk score and actionable prevention policy.
    """
    try:
        raw_url = payload.url.strip()
        analysis = risk_engine.analyze_url(raw_url)
        
        scan_id = f"url_{uuid.uuid4().hex[:10]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        record = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "type": "url",
            **analysis
        }

        # Store in persistent SQLite database
        storage.save_scan(record)

        return record

    except Exception as e:
        logger.error(f"Error during URL analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@app.post("/api/v1/analyze/email", response_model=EmailAnalysisResponse, tags=["Threat Analysis"])
def analyze_email_endpoint(payload: EmailAnalysisRequest):
    """
    Evaluates email metadata, social engineering urgency patterns, and scans embedded URLs.
    """
    try:
        analysis = email_analyzer.analyze_email(
            sender=payload.sender,
            subject=payload.subject,
            body=payload.body,
            reply_to=payload.reply_to
        )

        scan_id = f"em_{uuid.uuid4().hex[:10]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        record = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "type": "email",
            **analysis
        }

        storage.save_scan(record)

        return record

    except Exception as e:
        logger.error(f"Error during Email analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email analysis failed: {str(e)}"
        )

    except Exception as e:
        logger.error(f"Error during Email analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email analysis failed: {str(e)}"
        )


# Mount frontend directory for easy serving
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend"))
if os.path.exists(frontend_dir):
    app.mount("/dashboard", StaticFiles(directory=frontend_dir, html=True), name="frontend")
