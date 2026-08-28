"""
Integration tests for the FastAPI REST Service.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "service" in data


def test_model_info_endpoint():
    response = client.get("/api/v1/model/info")
    assert response.status_code == 200
    data = response.json()
    assert "champion_model" in data
    assert "test_metrics" in data
    assert "all_model_results" in data


def test_url_analysis_endpoint():
    payload = {"url": "http://paypa1-update-security-account.com/login.php"}
    response = client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert data["risk_score"] >= 0
    assert data["action"] in ["ALLOW", "WARN", "STRONG_WARNING", "BLOCK"]
    assert "reasons" in data


def test_email_analysis_endpoint():
    payload = {
        "sender": "Chase Bank <alert@chase-portal.xyz>",
        "subject": "Immediate Action Required: Unusual Activity Detected",
        "body": "Your bank account has been locked. Click here to verify: http://chase-bank-online-alert.account-update921.info/login",
        "reply_to": "attacker@drop.net"
    }
    response = client.post("/api/v1/analyze/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "phishing"
    assert data["risk_score"] >= 60
    assert len(data["threat_signals"]) > 0


def test_stats_and_history_endpoints():
    stats_res = client.get("/api/v1/stats")
    assert stats_res.status_code == 200
    assert "total_scans" in stats_res.json()

    history_res = client.get("/api/v1/history")
    assert history_res.status_code == 200
    assert isinstance(history_res.json(), list)
