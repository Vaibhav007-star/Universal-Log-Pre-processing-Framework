"""
Persistent Learned Rule Store (SQLite) & Dynamic Compiled Regex Parsers.
Persists dynamically learned log grammars so the system improves continuously.
"""

import sqlite3
import json
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from parsers.base import BaseParser, IntermediateParseResult
from parsers.registry import ParserRegistry


class DynamicRegexParser(BaseParser):
    """
    A compiled parser instantiated dynamically from a learned regex specification.
    """
    def __init__(
        self,
        signature_id: str,
        regex_pattern: str,
        field_mappings: Dict[str, str],
        confidence_score: float = 0.85
    ):
        self.signature_id = signature_id
        self.name = f"jit_{signature_id}"
        self.priority = 65  # Higher than generic fallback, lower than strict RFC syntax
        self.supported_formats = ["JIT_INFERRED"]
        self.regex_str = regex_pattern
        self.compiled_regex = re.compile(regex_pattern)
        self.field_mappings = field_mappings
        self.confidence_score = confidence_score

    def can_parse(self, raw_log: str) -> Tuple[bool, float]:
        if self.compiled_regex.search(raw_log):
            return True, self.confidence_score
        return False, 0.0

    def parse(self, raw_log: str) -> IntermediateParseResult:
        m = self.compiled_regex.search(raw_log)
        if not m:
            return IntermediateParseResult(
                success=False,
                format_name="JIT_INFERRED",
                raw_log=raw_log,
                error_codes=["ERR_DYNAMIC_REGEX_MISMATCH"],
                parser_name=self.name
            )

        raw_extracted = m.groupdict()
        canonical_extracted: Dict[str, Any] = {}

        # Apply field mappings: mapped_name = self.field_mappings.get(regex_group_name, regex_group_name)
        for grp, val in raw_extracted.items():
            if val is not None and str(val).strip():
                target_key = self.field_mappings.get(grp, grp)
                canonical_extracted[target_key] = val.strip()

        # Find timestamp
        timestamp_raw = None
        for k in ("timestamp", "time", "date", "event_time", "datetime"):
            if k in canonical_extracted:
                timestamp_raw = canonical_extracted[k]
                break

        return IntermediateParseResult(
            success=True,
            format_name="JIT_INFERRED",
            extracted_fields=canonical_extracted,
            timestamp_raw=timestamp_raw,
            raw_log=raw_log,
            is_exact_syntax=True,
            parser_name=self.name
        )


class LearnedRuleStore:
    """
    SQLite persistence layer for dynamically synthesized parsers.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS learned_rules (
                    signature_id TEXT PRIMARY KEY,
                    template_str TEXT NOT NULL,
                    regex_pattern TEXT NOT NULL,
                    field_mappings TEXT NOT NULL,
                    sample_logs TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    times_used INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    is_verified_by_analyst INTEGER DEFAULT 0
                )
            """)
            conn.commit()

    def save_rule(
        self,
        signature_id: str,
        template_str: str,
        regex_pattern: str,
        field_mappings: Dict[str, str],
        sample_logs: List[str],
        confidence_score: float = 0.85,
        is_verified: bool = False
    ) -> bool:
        """
        Inserts or updates a learned rule.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO learned_rules (
                    signature_id, template_str, regex_pattern, field_mappings,
                    sample_logs, confidence_score, created_at, is_verified_by_analyst
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(signature_id) DO UPDATE SET
                    regex_pattern = excluded.regex_pattern,
                    field_mappings = excluded.field_mappings,
                    confidence_score = excluded.confidence_score,
                    is_verified_by_analyst = excluded.is_verified_by_analyst
            """, (
                signature_id,
                template_str,
                regex_pattern,
                json.dumps(field_mappings),
                json.dumps(sample_logs),
                confidence_score,
                now,
                1 if is_verified else 0
            ))
            conn.commit()
        return True

    def get_rule(self, signature_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT * FROM learned_rules WHERE signature_id = ?", (signature_id,))
            row = cur.fetchone()
            if row:
                d = dict(row)
                d["field_mappings"] = json.loads(d["field_mappings"])
                d["sample_logs"] = json.loads(d["sample_logs"])
                return d
        return None

    def list_rules(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT * FROM learned_rules ORDER BY created_at DESC")
            rules = []
            for row in cur.fetchall():
                d = dict(row)
                d["field_mappings"] = json.loads(d["field_mappings"])
                d["sample_logs"] = json.loads(d["sample_logs"])
                rules.append(d)
            return rules

    def increment_usage(self, signature_id: str):
        with self._get_conn() as conn:
            conn.execute("UPDATE learned_rules SET times_used = times_used + 1 WHERE signature_id = ?", (signature_id,))
            conn.commit()

    def load_all_into_registry(self, registry: ParserRegistry) -> int:
        """
        Instantiates DynamicRegexParser for each saved rule and registers it into the ParserRegistry.
        """
        rules = self.list_rules()
        count = 0
        for r in rules:
            try:
                parser = DynamicRegexParser(
                    signature_id=r["signature_id"],
                    regex_pattern=r["regex_pattern"],
                    field_mappings=r["field_mappings"],
                    confidence_score=r["confidence_score"]
                )
                registry.register(parser)
                count += 1
            except Exception as e:
                print(f"[WARN] Failed to load dynamic rule {r['signature_id']}: {e}")
        return count

