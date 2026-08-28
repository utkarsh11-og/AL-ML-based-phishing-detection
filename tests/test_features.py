"""
Unit tests for URL feature extraction.
"""

import pytest
from ml.features.url_features import URLFeatureExtractor


@pytest.fixture
def extractor():
    return URLFeatureExtractor()


def test_entropy_calculation(extractor):
    # Homogeneous string has 0 entropy
    assert extractor.calculate_entropy("aaaaaa") == 0.0
    # Empty string has 0 entropy
    assert extractor.calculate_entropy("") == 0.0
    # Random characters should have positive entropy
    assert extractor.calculate_entropy("abcdef123456") > 3.0


def test_ip_address_detection(extractor):
    ip_url = "http://192.168.1.1/login.php"
    features = extractor.extract_features(ip_url)
    assert features["has_ip_address"] == 1

    normal_url = "https://www.google.com"
    features = extractor.extract_features(normal_url)
    assert features["has_ip_address"] == 0


def test_at_symbol_detection(extractor):
    deceptive_url = "http://paypal.com@evil-site.com/verify"
    features = extractor.extract_features(deceptive_url)
    assert features["num_at_symbols"] == 1


def test_keyword_count(extractor):
    phish_url = "http://secure-login-update-banking.com/auth"
    features = extractor.extract_features(phish_url)
    assert features["keyword_count"] >= 3  # secure, login, update, banking
