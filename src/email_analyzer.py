"""
Email Phishing Detection & Social Engineering Analysis Engine.

Analyzes:
1. Sender & Reply-To address inconsistencies (Domain spoofing / display name deception).
2. Urgency & Coercive Social Engineering language heuristics.
3. Embedded hyperlink extraction & automated URL Risk Engine scanning.
4. Aggregated email threat verdict (0-100 Score, ALLOW/WARN/BLOCK).
"""

import os
import sys
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.risk_engine import RiskEngine


class EmailPhishingAnalyzer:
    """
    Evaluates email metadata, textual content, and embedded URLs to detect social engineering.
    """

    # High-pressure / Coercive phrases common in phishing campaigns
    URGENCY_PATTERNS = [
        r"\b(?:immediate(?:ly)?|urgent|urgently|action required)\b",
        r"\b(?:account (?:suspended|restricted|disabled|locked|terminated))\b",
        r"\b(?:within 24 hours|within 48 hours|deadline|expires soon)\b",
        r"\b(?:unauthorized (?:activity|access|transaction|login))\b",
        r"\b(?:verify your identity|confirm your identity|update billing)\b",
        r"\b(?:tax refund|irs notice|wire transfer|direct deposit)\b",
        r"\b(?:password (?:expired|compromised|reset required))\b",
        r"\b(?:gift card|winner|claim prize|crypto bonus|airdrop)\b",
        r"\b(?:click (?:here|below|the link)|scan the qr code)\b",
    ]

    # Legitimate primary domains for impersonated organizations
    OFFICIAL_BRAND_DOMAINS = {
        "paypal": ["paypal.com"],
        "apple": ["apple.com", "icloud.com"],
        "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
        "google": ["google.com", "gmail.com"],
        "amazon": ["amazon.com", "aws.com"],
        "netflix": ["netflix.com"],
        "chase": ["chase.com", "jpmorgan.com"],
        "bank of america": ["bankofamerica.com", "bofa.com"],
        "wells fargo": ["wellsfargo.com"],
        "citi": ["citi.com", "citigroup.com"],
        "binance": ["binance.com"],
        "coinbase": ["coinbase.com"],
        "metamask": ["metamask.io"],
        "dhl": ["dhl.com"],
        "fedex": ["fedex.com"],
        "usps": ["usps.gov", "usps.com"],
        "facebook": ["facebook.com", "meta.com"],
        "instagram": ["instagram.com"]
    }

    URL_REGEX = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*")

    def __init__(self, risk_engine: Optional[RiskEngine] = None):
        self.risk_engine = risk_engine or RiskEngine()

    def _extract_email_address(self, raw_sender: str) -> str:
        """Extracts plain email from 'Display Name <email@domain.com>' format."""
        match = re.search(r"<([^>]+)>", raw_sender)
        if match:
            return match.group(1).strip().lower()
        return raw_sender.strip().lower()

    def analyze_sender(self, sender: str, reply_to: Optional[str] = None) -> List[Dict[str, str]]:
        """Detects sender address anomalies, brand impersonation, and reply-to mismatches."""
        signals = []
        sender_lower = sender.lower()
        sender_email = self._extract_email_address(sender)
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

        # 1. Brand Impersonation in Display Name or Lookalike Domain
        for brand, official_domains in self.OFFICIAL_BRAND_DOMAINS.items():
            brand_in_display = brand in sender_lower
            brand_in_domain = brand in sender_domain
            
            # If brand is referenced, verify if the sender domain matches official domains
            is_official = any(sender_domain == dom or sender_domain.endswith("." + dom) for dom in official_domains)
            
            if (brand_in_display or brand_in_domain) and not is_official and sender_domain:
                signals.append({
                    "severity": "critical",
                    "code": "BRAND_SPOOFING",
                    "title": f"Suspected Brand Impersonation ({brand.title()})",
                    "description": f"The sender claims affiliation with '{brand.title()}', but the email originates from an unauthorized domain: '{sender_domain}'."
                })
                break

        # 2. Reply-To Mismatch
        if reply_to:
            reply_email = self._extract_email_address(reply_to)
            reply_domain = reply_email.split("@")[-1] if "@" in reply_email else ""
            if reply_domain and sender_domain and reply_domain != sender_domain:
                signals.append({
                    "severity": "warning",
                    "code": "REPLY_TO_MISMATCH",
                    "title": "Reply-To Address Mismatch",
                    "description": f"Replies will be routed to '{reply_domain}' instead of the sender domain '{sender_domain}'. This is a frequent indicator of return-path redirection."
                })

        return signals

    def analyze_text_urgency(self, subject: str, body: str) -> List[Dict[str, str]]:
        """Scans subject and body text for psychological coercion triggers."""
        signals = []
        combined_text = f"{subject}\n{body}".lower()

        matched_phrases = []
        for pattern in self.URGENCY_PATTERNS:
            matches = re.findall(pattern, combined_text)
            if matches:
                matched_phrases.extend(matches)

        if len(matched_phrases) >= 2:
            signals.append({
                "severity": "warning",
                "code": "HIGH_URGENCY_PRESSURE",
                "title": f"High Social Engineering Urgency ({len(matched_phrases)} coercive indicators)",
                "description": f"The email employs artificial urgency triggers (e.g. '{matched_phrases[0]}') designed to induce panic and force rapid user compliance."
            })
        elif len(matched_phrases) == 1:
            signals.append({
                "severity": "info",
                "code": "URGENCY_TRIGGER",
                "title": "Urgency Indicator Detected",
                "description": f"Contains urgency phrasing: '{matched_phrases[0]}'."
            })

        return signals

    def extract_and_analyze_urls(self, body: str) -> List[Dict[str, Any]]:
        """Finds all hyperlinks in email body and runs full RiskEngine evaluation on each."""
        raw_urls = self.URL_REGEX.findall(body)
        unique_urls = list(dict.fromkeys(raw_urls))  # Deduplicate while preserving order

        analyzed = []
        for url in unique_urls:
            url_clean = url.rstrip(".,;!?'\")>")
            res = self.risk_engine.analyze_url(url_clean)
            analyzed.append(res)

        return analyzed

    def analyze_email(
        self,
        sender: str,
        subject: str,
        body: str,
        reply_to: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Complete end-to-end email analysis synthesizing sender authenticity,
        content urgency, and embedded URL security.
        """
        sender_signals = self.analyze_sender(sender, reply_to)
        urgency_signals = self.analyze_text_urgency(subject, body)
        url_results = self.extract_and_analyze_urls(body)

        all_signals = sender_signals + urgency_signals

        # Calculate Aggregated Risk Score
        max_url_score = max([u["risk_score"] for u in url_results], default=0)
        
        email_base_score = 10.0
        
        # Add points for sender issues
        if any(s["severity"] == "critical" for s in sender_signals):
            email_base_score += 40.0
        elif any(s["severity"] == "warning" for s in sender_signals):
            email_base_score += 20.0

        # Add points for urgency signals
        if any(s["severity"] == "warning" for s in urgency_signals):
            email_base_score += 25.0
        elif any(s["severity"] == "info" for s in urgency_signals):
            email_base_score += 10.0

        # Blended score: URL threat is heavily weighted if malicious
        if max_url_score > 60:
            final_risk = int(round(max(max_url_score, email_base_score)))
        else:
            final_risk = int(round(min(100.0, max(0.0, (email_base_score * 0.6) + (max_url_score * 0.4)))))

        policy = self.risk_engine.determine_policy_action(final_risk)

        return {
            "classification": "phishing" if final_risk >= self.risk_engine.THRESHOLD_MEDIUM else "legitimate",
            "risk_score": final_risk,
            "risk_level": policy["risk_level"],
            "action": policy["action"],
            "recommendation": policy["recommendation"],
            "sender": sender,
            "subject": subject,
            "threat_signals": all_signals,
            "embedded_urls_count": len(url_results),
            "embedded_urls_analysis": url_results,
        }


if __name__ == "__main__":
    analyzer = EmailPhishingAnalyzer()
    
    sample_email = {
        "sender": "PayPal Support <security-alert@update-portal-paypal.xyz>",
        "reply_to": "attacker-drop@tempmail.cc",
        "subject": "URGENT: Your PayPal Account Has Been Suspended!",
        "body": "Dear customer, unauthorized activity was detected on your account. Your account is locked within 24 hours unless you verify your identity now: http://paypal.com@secure-verify-account.xyz/login.php"
    }

    result = analyzer.analyze_email(**sample_email)
    print("\n" + "="*60)
    print("           EMAIL PHISHING ANALYSIS RESULT            ")
    print("="*60)
    print(f"Classification : {result['classification'].upper()} | Action: {result['action']}")
    print(f"Risk Score     : {result['risk_score']}/100 ({result['risk_level'].upper()})")
    print(f"Recommendation : {result['recommendation']}")
    print("\nThreat Signals:")
    for s in result["threat_signals"]:
        print(f"  [{s['severity'].upper()}] {s['title']}: {s['description']}")
    print(f"\nEmbedded URLs Found: {result['embedded_urls_count']}")
    for u in result["embedded_urls_analysis"]:
        print(f"  -> {u['url']} (Risk: {u['risk_score']}/100, Action: {u['action']})")
