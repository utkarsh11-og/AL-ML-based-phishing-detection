"""
Unit tests for Email Phishing and Social Engineering analysis.
"""

import pytest
from src.email_analyzer import EmailPhishingAnalyzer


@pytest.fixture
def email_analyzer():
    return EmailPhishingAnalyzer()


def test_brand_spoofing_detection(email_analyzer):
    sender = "PayPal Security <alert@fake-paypal-verify.xyz>"
    signals = email_analyzer.analyze_sender(sender)
    assert any(s["code"] == "BRAND_SPOOFING" for s in signals)


def test_reply_to_mismatch(email_analyzer):
    sender = "Support <support@company.com>"
    reply_to = "attacker@external-drop.net"
    signals = email_analyzer.analyze_sender(sender, reply_to)
    assert any(s["code"] == "REPLY_TO_MISMATCH" for s in signals)


def test_urgency_detection(email_analyzer):
    subject = "URGENT: Your account has been suspended within 24 hours!"
    body = "Immediate action required. Please confirm your identity or your account is terminated."
    signals = email_analyzer.analyze_text_urgency(subject, body)
    assert any(s["code"] in ["HIGH_URGENCY_PRESSURE", "URGENCY_TRIGGER"] for s in signals)


def test_end_to_end_phishing_email(email_analyzer):
    res = email_analyzer.analyze_email(
        sender="Apple Support <security@id-apple-notice.top>",
        subject="URGENT: Immediate Account Verification Required",
        body="Verify your ID within 24 hours: http://appleid.apple.com.account-verification-notice.xyz/signin",
        reply_to="drop@tempmail.cc"
    )
    assert res["risk_score"] >= 70
    assert res["classification"] == "phishing"
    assert res["embedded_urls_count"] == 1
