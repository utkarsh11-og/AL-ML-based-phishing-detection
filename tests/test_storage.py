"""
Unit tests for Persistent SQLite Telemetry and Audit Storage.
"""

import os
import uuid
import pytest
from src.storage import StorageManager


@pytest.fixture
def storage():
    # Use unique DB file per test run
    test_db = f"test_scans_{uuid.uuid4().hex[:8]}.db"
    mgr = StorageManager(db_path=test_db)
    yield mgr
    try:
        if os.path.exists(test_db):
            os.remove(test_db)
    except Exception:
        pass


def test_save_and_retrieve_scan(storage):
    record = {
        "scan_id": "test_url_001",
        "type": "url",
        "url": "https://www.google.com",
        "classification": "legitimate",
        "risk_score": 10,
        "risk_level": "low",
        "action": "ALLOW",
        "model_confidence": 0.12,
        "model_name": "Random Forest",
        "reasons": [{"severity": "info", "code": "OK", "title": "Safe", "description": "Safe URL"}],
        "features": {"url_length": 22}
    }
    
    storage.save_scan(record)
    history = storage.get_recent_scans(limit=10)
    assert len(history) == 1
    assert history[0]["scan_id"] == "test_url_001"
    assert history[0]["classification"] == "legitimate"


def test_telemetry_stats_calculation(storage):
    storage.save_scan({
        "scan_id": "scan_1",
        "type": "url",
        "url": "https://good.com",
        "classification": "legitimate",
        "risk_score": 10,
        "action": "ALLOW"
    })
    storage.save_scan({
        "scan_id": "scan_2",
        "type": "url",
        "url": "http://evil.com/login",
        "classification": "phishing",
        "risk_score": 90,
        "action": "BLOCK"
    })

    stats = storage.get_stats()
    assert stats["total_scans"] == 2
    assert stats["phishing_count"] == 1
    assert stats["legitimate_count"] == 1
    assert stats["average_risk_score"] == 50.0
