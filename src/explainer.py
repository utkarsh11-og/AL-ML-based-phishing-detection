"""
Explainable AI (XAI) & Security Signal Attribution Module.

Translates numeric feature vectors and model decisions into
human-readable security explanations for security analysts and end-users.
"""

from typing import Dict, List, Any


class FeatureExplainer:
    """
    Analyzes raw feature values to produce human-interpretable security reasons.
    """

    @staticmethod
    def explain_url_features(features: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Evaluates features and returns a list of prioritized security reasons
        with severity levels: 'critical', 'warning', 'info'.
        """
        reasons = []

        # 1. IP Address Hostname (High Severity)
        if features.get("has_ip_address", 0) == 1:
            reasons.append({
                "severity": "critical",
                "code": "IP_HOSTNAME",
                "title": "Raw IP Address Used as Hostname",
                "description": "Legitimate organizations rarely use raw IP addresses (e.g. 192.168.x.x) for public websites. This is often used to evade domain-based reputation filters."
            })

        # 2. Deceptive '@' Symbol (High Severity)
        if features.get("num_at_symbols", 0) > 0:
            reasons.append({
                "severity": "critical",
                "code": "AT_SYMBOL_DECEPTION",
                "title": "Deceptive '@' Character in URL",
                "description": "The '@' symbol causes browsers to ignore all preceding characters (e.g., paypal.com@evil.com) and connect directly to the host that follows."
            })

        # 3. Double Slash Redirect (High Severity)
        if features.get("has_double_slash_redirect", 0) == 1:
            reasons.append({
                "severity": "critical",
                "code": "DOUBLE_SLASH_REDIRECT",
                "title": "Embedded '//' Redirect Pattern",
                "description": "An unexpected '//' in the URL path is commonly used to trick web servers into redirecting victims to external attacker infrastructure."
            })

        # 4. Excessive Subdomains (Medium Severity)
        subdomains = features.get("num_subdomains", 0)
        if subdomains >= 3:
            reasons.append({
                "severity": "warning",
                "code": "DEEP_SUBDOMAIN_CHAIN",
                "title": f"Excessive Subdomain Depth ({subdomains} levels)",
                "description": "Deep subdomain nesting is frequently used to mimic trusted brand names (e.g., login.chase.com.security-portal.xyz)."
            })
        elif subdomains == 2:
            reasons.append({
                "severity": "info",
                "code": "MULTI_SUBDOMAIN",
                "title": "Multiple Subdomains Present",
                "description": "The URL contains multiple subdomain components."
            })

        # 5. Shannon Entropy (Randomness / Obfuscation)
        url_entropy = features.get("url_entropy", 0.0)
        if url_entropy > 4.5:
            reasons.append({
                "severity": "warning",
                "code": "HIGH_ENTROPY",
                "title": f"High Character Randomness (Entropy: {url_entropy:.2f})",
                "description": "High string entropy indicates algorithmically generated domains (DGAs), random tokens, or obfuscated hex/base64 payloads."
            })

        # 6. Sensitive Authentication Keywords
        keyword_count = features.get("keyword_count", 0)
        if keyword_count >= 2:
            reasons.append({
                "severity": "warning",
                "code": "SENSITIVE_KEYWORDS",
                "title": f"Multiple Targeted Security Keywords ({keyword_count} detected)",
                "description": "The URL heavily features words commonly targeted in credential harvesting (e.g., 'login', 'verify', 'update', 'banking')."
            })
        elif keyword_count == 1:
            reasons.append({
                "severity": "info",
                "code": "AUTH_KEYWORD",
                "title": "Security Keyword Present",
                "description": "URL includes sensitive terms related to account authentication."
            })

        # 7. Unusually Long URL / Hostname
        url_len = features.get("url_length", 0)
        if url_len > 75:
            reasons.append({
                "severity": "warning",
                "code": "EXCESSIVE_URL_LENGTH",
                "title": f"Excessive URL Length ({url_len} chars)",
                "description": "Attackers construct lengthy URLs to push suspicious hostnames out of view in mobile browser address bars."
            })

        # 8. Protocol Inspection
        if features.get("is_https", 0) == 0:
            reasons.append({
                "severity": "info",
                "code": "UNENCRYPTED_HTTP",
                "title": "Unencrypted HTTP Protocol",
                "description": "Connection is not encrypted with HTTPS. Modern authentication forms should always utilize TLS encryption."
            })

        # 9. Digit Concentration
        digit_ratio = features.get("digit_ratio", 0.0)
        if digit_ratio > 0.15:
            reasons.append({
                "severity": "info",
                "code": "HIGH_DIGIT_DENSITY",
                "title": f"Elevated Numeric Density ({digit_ratio:.1%})",
                "description": "A high proportion of numerical digits is characteristic of session trackers or random host variations."
            })

        # If no flags triggered, provide safe indicator
        if not reasons:
            reasons.append({
                "severity": "info",
                "code": "STANDARD_STRUCTURE",
                "title": "Standard Lexical Structure",
                "description": "No anomalous lexical or structural phishing indicators were identified."
            })

        return reasons
