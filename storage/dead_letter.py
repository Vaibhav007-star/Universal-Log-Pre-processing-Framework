"""
Dead-Letter Queue Preservation Sink.
Ensures zero data loss by recording unparseable or rejected raw logs with diagnostic metadata.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import config


class DeadLetterSink:
    """
    Appends low-confidence or malformed logs to a persistent JSONL audit file.
    """

    def __init__(self, file_path: str = config.DEAD_LETTER_PATH):
        self.file_path = file_path

    def write_dead_letter(
        self,
        event_id: str,
        raw_log: str,
        reason_codes: List[str],
        extracted_fields: Dict[str, Any],
        confidence_score: float,
        warnings: List[str]
    ):
        record = {
            "dead_letter_time": datetime.now(timezone.utc).isoformat(),
            "event_id": event_id,
            "reason_codes": reason_codes,
            "confidence_score": confidence_score,
            "extracted_fields": extracted_fields,
            "warnings": warnings,
            "raw_log": raw_log
        }
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

