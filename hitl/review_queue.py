"""
Persistent SQLite-backed Review Queue for Low-Confidence Log Events.
"""

import sqlite3
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import config


class ReviewQueue:
    """
    Manages low-confidence logs that require cybersecurity analyst triage.
    """

    def __init__(self, db_path: str = config.REVIEW_QUEUE_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS review_queue (
                    event_id TEXT PRIMARY KEY,
                    raw_log TEXT NOT NULL,
                    format_detected TEXT NOT NULL,
                    extracted_fields TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    confidence_breakdown TEXT NOT NULL,
                    warnings TEXT NOT NULL,
                    status TEXT DEFAULT 'PENDING',
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

    def enqueue(
        self,
        event_id: str,
        raw_log: str,
        format_detected: str,
        extracted_fields: Dict[str, Any],
        confidence_score: float,
        confidence_breakdown: Dict[str, float],
        warnings: List[str]
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO review_queue (
                    event_id, raw_log, format_detected, extracted_fields,
                    confidence_score, confidence_breakdown, warnings, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
            """, (
                event_id,
                raw_log,
                format_detected,
                json.dumps(extracted_fields),
                confidence_score,
                json.dumps(confidence_breakdown),
                json.dumps(warnings),
                now
            ))
            conn.commit()
        return True

    def get_pending(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("""
                SELECT * FROM review_queue
                WHERE status = 'PENDING'
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = []
            for r in cur.fetchall():
                d = dict(r)
                d["extracted_fields"] = json.loads(d["extracted_fields"])
                d["confidence_breakdown"] = json.loads(d["confidence_breakdown"])
                d["warnings"] = json.loads(d["warnings"])
                rows.append(d)
            return rows

    def mark_status(self, event_id: str, status: str):
        with self._get_conn() as conn:
            conn.execute("UPDATE review_queue SET status = ? WHERE event_id = ?", (status, event_id))
            conn.commit()

