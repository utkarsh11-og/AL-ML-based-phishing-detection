"""
Persistent SQLite Telemetry & Audit Storage for Scan History.

Stores all scan records, timestamps, feature vectors, and enforced prevention actions.
"""

import os
import sqlite3
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

DB_PATH = "scans.db"


class StorageManager:
    """
    Manages persistent SQLite storage for real-time cybersecurity telemetry.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Creates tables if not already present."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    scan_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    action TEXT NOT NULL,
                    model_confidence REAL,
                    model_name TEXT,
                    reasons_json TEXT,
                    features_json TEXT
                )
            """)
            conn.commit()

    def save_scan(self, record: Dict[str, Any]):
        """Persists a new scan record."""
        target = record.get("url") if record.get("type") == "url" else f"{record.get('subject', '')} ({record.get('sender', '')})"
        reasons_json = json.dumps(record.get("reasons") or record.get("threat_signals") or [])
        features_json = json.dumps(record.get("features") or {})

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scan_logs (
                    scan_id, timestamp, scan_type, target, classification,
                    risk_score, risk_level, action, model_confidence, model_name,
                    reasons_json, features_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.get("scan_id"),
                record.get("timestamp", datetime.now(timezone.utc).isoformat()),
                record.get("type", "url"),
                target,
                record.get("classification"),
                record.get("risk_score", 0),
                record.get("risk_level", "low"),
                record.get("action", "ALLOW"),
                record.get("model_confidence", 0.0),
                record.get("model_name", "Random Forest"),
                reasons_json,
                features_json
            ))
            conn.commit()

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent scans ordered by timestamp descending."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM scan_logs ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append({
                "scan_id": r["scan_id"],
                "timestamp": r["timestamp"],
                "type": r["scan_type"],
                "target": r["target"],
                "url": r["target"] if r["scan_type"] == "url" else None,
                "classification": r["classification"],
                "risk_score": r["risk_score"],
                "risk_level": r["risk_level"],
                "action": r["action"],
                "model_confidence": r["model_confidence"],
                "model_name": r["model_name"],
                "reasons": json.loads(r["reasons_json"]),
                "features": json.loads(r["features_json"])
            })
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Calculates aggregated real-time telemetry metrics."""
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scan_logs").fetchone()[0]
            if total == 0:
                return {
                    "total_scans": 0,
                    "phishing_count": 0,
                    "legitimate_count": 0,
                    "average_risk_score": 0.0,
                    "recent_threats_count": 0
                }
            
            phish = conn.execute("SELECT COUNT(*) FROM scan_logs WHERE classification = 'phishing'").fetchone()[0]
            legit = total - phish
            avg_score = conn.execute("SELECT AVG(risk_score) FROM scan_logs").fetchone()[0] or 0.0
            recent_threats = conn.execute("""
                SELECT COUNT(*) FROM (
                    SELECT classification FROM scan_logs ORDER BY timestamp DESC LIMIT 10
                ) WHERE classification = 'phishing'
            """).fetchone()[0]

            return {
                "total_scans": total,
                "phishing_count": phish,
                "legitimate_count": legit,
                "average_risk_score": round(float(avg_score), 2),
                "recent_threats_count": recent_threats
            }

    def clear_all_scans(self):
        """Deletes all persistent audit scan records."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM scan_logs")
            conn.commit()
