"""
Unit tests for the Security Risk Engine & Policy Layer.
"""

import pytest
from src.risk_engine import RiskEngine


@pytest.fixture
def risk_engine():
    return RiskEngine()


def test_legitimate_url_risk_score(risk_engine):
    res = risk_engine.analyze_url("https://www.google.com/maps")
    assert res["risk_score"] < 30
    assert res["risk_level"] == "low"
    assert res["action"] == "ALLOW"
    assert res["classification"] == "legitimate"


def test_phishing_url_risk_score(risk_engine):
    res = risk_engine.analyze_url("http://paypal.com@secure-verify-update.xyz/login.php")
    assert res["risk_score"] >= 80
    assert res["risk_level"] == "critical"
    assert res["action"] == "BLOCK"
    assert res["classification"] == "phishing"


def test_ip_address_modifier(risk_engine):
    # An IP address with sensitive keyword should trigger medium/high risk
    res = risk_engine.analyze_url("http://192.168.1.1/admin/login.php")
    assert any(r["code"] == "IP_HOSTNAME" for r in res["reasons"])
    assert res["risk_score"] >= 40
