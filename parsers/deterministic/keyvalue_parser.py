"""
Key-Value and Delimited Format Deterministic Parser.
Parses logs composed primarily of key=value or key:value pairs.
"""

import re
from typing import Tuple, Dict, Any
from parsers.base import BaseParser, IntermediateParseResult


class KeyValueParser(BaseParser):
    name = "keyvalue_deterministic"
    priority = 70
    supported_formats = ["KEY_VALUE"]

    # Match key=val or key="val" or key='val' or key: val
    KV_PATTERN = re.compile(r'([a-zA-Z0-9_\-\.]+)(?:=|\s*:\s*)(?:"([^"]*)"|\'([^\']*)\'|(\S+))')

    def can_parse(self, raw_log: str) -> Tuple[bool, float]:
        s = raw_log.strip()
        # Count number of key-value matches
        matches = self.KV_PATTERN.findall(s)
        if len(matches) >= 3:
            # Significant key-value structure
            confidence = min(0.90, 0.50 + (len(matches) * 0.08))
            return True, confidence
        return False, 0.0

    def parse(self, raw_log: str) -> IntermediateParseResult:
        s = raw_log.strip()
        matches = self.KV_PATTERN.findall(s)
        if not matches:
            return IntermediateParseResult(
                success=False,
                format_name="KEY_VALUE",
                raw_log=raw_log,
                error_codes=["ERR_NO_KV_PAIRS_FOUND"],
                is_exact_syntax=False,
                parser_name=self.name
            )

        extracted: Dict[str, Any] = {}
        for k, q_double, q_single, unquoted in matches:
            val = q_double if q_double else (q_single if q_single else unquoted)
            extracted[k.strip()] = val.strip()

        # Find potential timestamp
        timestamp_raw = None
        for ts_key in ("timestamp", "time", "datetime", "date", "ts", "@timestamp"):
            if ts_key in extracted:
                timestamp_raw = extracted[ts_key]
                break

        return IntermediateParseResult(
            success=True,
            format_name="KEY_VALUE",
            extracted_fields=extracted,
            timestamp_raw=timestamp_raw,
            raw_log=raw_log,
            is_exact_syntax=True,
            parser_name=self.name
        )

