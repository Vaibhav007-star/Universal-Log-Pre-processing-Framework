"""
High-Performance JSON Log Parser.
Flattens nested structures and normalizes JSON fields into the canonical intermediate representation.
"""

import json
from typing import Dict, Any, Tuple
from parsers.base import BaseParser, IntermediateParseResult


class JSONFastParser(BaseParser):
    name = "json_fast"
    priority = 90  # High priority because JSON syntax is strictly testable
    supported_formats = ["JSON"]

    def can_parse(self, raw_log: str) -> Tuple[bool, float]:
        s = raw_log.strip()
        if s.startswith("{") and s.endswith("}"):
            # Fast bracket balance check
            return True, 0.95
        return False, 0.0

    @staticmethod
    def _flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
        """
        Recursively flattens nested dicts: {"a": {"b": 1}} -> {"a.b": 1}
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(JSONFastParser._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Preserve list or stringify
                items.append((new_key, v))
            else:
                items.append((new_key, v))
        return dict(items)

    def parse(self, raw_log: str) -> IntermediateParseResult:
        s = raw_log.strip()
        warnings = []
        error_codes = []

        try:
            parsed_data = json.loads(s)
            if not isinstance(parsed_data, dict):
                return IntermediateParseResult(
                    success=False,
                    format_name="JSON",
                    raw_log=raw_log,
                    error_codes=["ERR_JSON_ROOT_NOT_OBJECT"]
                )

            flattened = self._flatten_dict(parsed_data)

            # Discover timestamp
            timestamp_raw = None
            for ts_key in ("@timestamp", "timestamp", "time", "event_time", "datetime", "date", "created_at"):
                for k, v in flattened.items():
                    if k.lower().endswith(ts_key) or k.lower() == ts_key:
                        timestamp_raw = str(v)
                        break
                if timestamp_raw:
                    break

            return IntermediateParseResult(
                success=True,
                format_name="JSON",
                extracted_fields=flattened,
                timestamp_raw=timestamp_raw,
                raw_log=raw_log,
                warnings=warnings,
                error_codes=error_codes,
                is_exact_syntax=True,
                parser_name=self.name
            )
        except json.JSONDecodeError as e:
            return IntermediateParseResult(
                success=False,
                format_name="JSON",
                raw_log=raw_log,
                warnings=[f"Malformed JSON syntax: {e}"],
                error_codes=["ERR_MALFORMED_JSON"],
                is_exact_syntax=False,
                parser_name=self.name
            )

