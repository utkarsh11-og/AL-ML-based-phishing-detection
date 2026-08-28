"""
URL Feature Extractor for Phishing Detection.

Extracts lexical, structural, statistical, and security-specific features
from raw URL strings without making live network requests (SSRF-safe static analysis).
"""

import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, Union
import tldextract


class URLFeatureExtractor:
    """
    Extracts security-relevant numeric and boolean features from a raw URL.
    """

    # Common targeted keywords in phishing attacks
    SUSPICIOUS_KEYWORDS = [
        "login", "signin", "verify", "verification", "account", "banking",
        "update", "security", "confirm", "wallet", "admin", "password",
        "credential", "recover", "authenticate", "billing", "support",
        "service", "free", "bonus", "ebayisapi", "webscr"
    ]

    # Regex pattern to match IPv4 addresses
    IPV4_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )

    def __init__(self):
        # Initialize tldextract with cache to speed up domain parsing
        self.tld_extractor = tldextract.TLDExtract(cache_dir=None)

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """
        Calculates the Shannon Entropy of a string.
        Higher values indicate higher randomness / obfuscation.
        """
        if not text:
            return 0.0
        
        length = len(text)
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        for count in char_counts.values():
            p = count / length
            entropy -= p * math.log2(p)
            
        return round(entropy, 4)

    def extract_features(self, url: str) -> Dict[str, Union[int, float]]:
        """
        Extracts a dictionary of numeric features from a single URL string.
        """
        if not isinstance(url, str) or not url.strip():
            url = ""

        raw_url = url.strip()
        
        # Ensure scheme is present for urlparse to parse netloc correctly
        if not raw_url.startswith(("http://", "https://")):
            parsed_url = urlparse("http://" + raw_url)
            is_https = 0
        else:
            parsed_url = urlparse(raw_url)
            is_https = 1 if parsed_url.scheme.lower() == "https" else 0

        hostname = parsed_url.netloc or ""
        path = parsed_url.path or ""
        query = parsed_url.query or ""

        # Remove port from hostname if present
        if ":" in hostname and not self.IPV4_PATTERN.match(hostname):
            hostname = hostname.split(":")[0]

        # Extract domain breakdown via tldextract
        extracted_tld = self.tld_extractor(hostname)
        subdomain = extracted_tld.subdomain
        domain = extracted_tld.domain
        suffix = extracted_tld.suffix

        # Subdomain count
        num_subdomains = len(subdomain.split(".")) if subdomain else 0

        # Check if hostname is an IP address
        has_ip = 1 if self.IPV4_PATTERN.match(hostname) else 0

        # Lexical counts
        url_len = len(raw_url)
        hostname_len = len(hostname)
        path_len = len(path)
        query_len = len(query)

        num_dots = raw_url.count(".")
        num_hyphens = raw_url.count("-")
        num_underscores = raw_url.count("_")
        num_slashes = raw_url.count("/")
        num_questionmarks = raw_url.count("?")
        num_equal_signs = raw_url.count("=")
        num_at_symbols = raw_url.count("@")
        num_percent_signs = raw_url.count("%")
        num_ampersands = raw_url.count("&")

        # Digit statistics
        num_digits = sum(c.isdigit() for c in raw_url)
        digit_ratio = round(num_digits / url_len, 4) if url_len > 0 else 0.0

        # Sensitive keywords count
        lower_url = raw_url.lower()
        keyword_count = sum(1 for kw in self.SUSPICIOUS_KEYWORDS if kw in lower_url)

        # Shannon Entropy
        url_entropy = self.calculate_entropy(raw_url)
        hostname_entropy = self.calculate_entropy(hostname)

        # Suspicious structural patterns
        has_double_slash_redirect = 1 if "//" in raw_url[7:] else 0  # Ignore http:// or https://

        return {
            "url_length": url_len,
            "hostname_length": hostname_len,
            "path_length": path_len,
            "query_length": query_len,
            "num_dots": num_dots,
            "num_hyphens": num_hyphens,
            "num_underscores": num_underscores,
            "num_slashes": num_slashes,
            "num_questionmarks": num_questionmarks,
            "num_equal_signs": num_equal_signs,
            "num_at_symbols": num_at_symbols,
            "num_percent_signs": num_percent_signs,
            "num_ampersands": num_ampersands,
            "num_digits": num_digits,
            "digit_ratio": digit_ratio,
            "num_subdomains": num_subdomains,
            "has_ip_address": has_ip,
            "is_https": is_https,
            "has_double_slash_redirect": has_double_slash_redirect,
            "keyword_count": keyword_count,
            "url_entropy": url_entropy,
            "hostname_entropy": hostname_entropy,
        }


# Quick standalone demonstration
if __name__ == "__main__":
    extractor = URLFeatureExtractor()
    
    test_legit = "https://www.google.com/search?q=machine+learning"
    test_phish = "http://paypal.com@secure-billing-portal.com/login?id=9482"
    
    print("--- Legitimate URL Features ---")
    print(f"URL: {test_legit}")
    for k, v in extractor.extract_features(test_legit).items():
        print(f"  {k:28s}: {v}")

    print("\n--- Phishing URL Features ---")
    print(f"URL: {test_phish}")
    for k, v in extractor.extract_features(test_phish).items():
        print(f"  {k:28s}: {v}")
