"""
Pydantic Schemas for Request & Response Data Validation.
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="The raw URL string to analyze", min_length=1, max_length=2048)

    model_config = {
        "json_schema_extra": {
            "example": {
                "url": "http://paypa1-update-security-account.com/login.php"
            }
        }
    }


class ThreatReason(BaseModel):
    severity: str = Field(..., description="'critical', 'warning', or 'info'")
    code: str
    title: str
    description: str


class URLAnalysisResponse(BaseModel):
    scan_id: str
    timestamp: str
    url: str
    classification: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    action: str
    recommendation: str
    model_confidence: float
    model_name: str
    model_version: str
    reasons: List[ThreatReason]
    features: Dict[str, Any]


class EmailAnalysisRequest(BaseModel):
    sender: str = Field(..., description="Sender header (e.g., 'PayPal Support <support@evil.com>')")
    subject: str = Field(..., description="Email subject line")
    body: str = Field(..., description="Email body text with any embedded hyperlinks")
    reply_to: Optional[str] = Field(None, description="Optional Reply-To header")

    model_config = {
        "json_schema_extra": {
            "example": {
                "sender": "Security Team <security-alert@update-service.xyz>",
                "subject": "URGENT: Immediate Account Verification Required",
                "body": "Your account has been locked. Verify identity within 24 hours: http://paypal.com@secure-billing-portal.com/login",
                "reply_to": "attacker-drop@tempmail.cc"
            }
        }
    }


class EmailAnalysisResponse(BaseModel):
    scan_id: str
    timestamp: str
    classification: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    action: str
    recommendation: str
    sender: str
    subject: str
    threat_signals: List[ThreatReason]
    embedded_urls_count: int
    embedded_urls_analysis: List[Dict[str, Any]]


class HealthResponse(BaseModel):
    status: str
    service: str
    model_loaded: bool
    model_name: str
    model_version: str


class StatsResponse(BaseModel):
    total_scans: int
    phishing_count: int
    legitimate_count: int
    average_risk_score: float
    recent_threats_count: int
