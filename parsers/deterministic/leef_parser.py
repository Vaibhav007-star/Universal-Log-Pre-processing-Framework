"""
IBM QRadar Log Event Extended Format (LEEF) Deterministic Parser.
Supports LEEF 1.0 (tab-delimited) and LEEF 2.0 (custom delimiter).
"""

import re
from typing import Tuple, Dict, Any
from parsers.base import BaseParser, IntermediateParseResult


class LEEFParser(BaseParser):
    name = "leef_deterministic"
    priority = 84
    supported_formats = ["LEEF"]

    def can_parse(self, raw_log: str) -> Tuple[bool, float]:
        s = raw_log.strip()
        if s.startswith("LEEF:") or " LEEF:" in s:
            return True, 0.98
        return False, 0.0

    def parse(self, raw_log: str) -> IntermediateParseResult:
        s = raw_log.strip()
        warnings = []
        error_codes = []

        idx = s.find("LEEF:")
        if idx > 0:
            s = s[idx:]

        parts = re.split(r'(?<!\\)\|', s)
        if len(parts) < 6:
            return IntermediateParseResult(
                success=False,
                format_name="LEEF",
                raw_log=raw_log,
                warnings=[f"LEEF header has {len(parts)} segments, expected at least 6"],
                error_codes=["ERR_MALFORMED_LEEF_HEADER"],
                is_exact_syntax=False,
                parser_name=self.name
            )

        leef_version = parts[0].replace("LEEF:", "")
        vendor = parts[1]
        product = parts[2]
        version = parts[3]
        event_id = parts[4]

        delimiter = "\t"
        extension_str = ""

        if leef_version.startswith("2.") and len(parts) >= 7:
            delimiter = parts[5] if parts[5] else "\t"
            extension_str = "|".join(parts[6:])
        else:
            extension_str = "|".join(parts[5:])

        extracted: Dict[str, Any] = {
            "leef_version": leef_version,
            "device_vendor": vendor,
            "device_product": product,
            "device_version": version,
            "event_id": event_id,
        }

        # Parse key=values based on delimiter
        tokens = extension_str.split(delimiter)
        for token in tokens:
            token = token.strip()
            if "=" in token:
                k, v = token.split("=", 1)
                extracted[k.strip()] = v.strip()

        timestamp_raw = extracted.get("devTime") or extracted.get("calmTime")

        return IntermediateParseResult(
            success=True,
            format_name="LEEF",
            extracted_fields=extracted,
            timestamp_raw=timestamp_raw,
            raw_log=raw_log,
            warnings=warnings,
            error_codes=error_codes,
            is_exact_syntax=True,
            parser_name=self.name
        )

