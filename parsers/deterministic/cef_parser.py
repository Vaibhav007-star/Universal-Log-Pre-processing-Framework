"""
ArcSight Common Event Format (CEF) Deterministic Parser.
Parses standard 7-part pipe headers and escaped key=value extensions.
"""

import re
from typing import Tuple, Dict, Any
from parsers.base import BaseParser, IntermediateParseResult


class CEFParser(BaseParser):
    name = "cef_deterministic"
    priority = 85
    supported_formats = ["CEF"]

    # Extension tokenizer matching key=value pairs, allowing quoted strings or unquoted words
    KV_REGEX = re.compile(r'([a-zA-Z0-9_\-\.]+)=(?:"([^"\\]*(?:\\.[^"\\]*)*)"|(\S+))')

    def can_parse(self, raw_log: str) -> Tuple[bool, float]:
        s = raw_log.strip()
        if s.startswith("CEF:") or " CEF:" in s:
            return True, 0.98
        return False, 0.0

    def parse(self, raw_log: str) -> IntermediateParseResult:
        s = raw_log.strip()
        warnings = []
        error_codes = []

        # Find prefix start if embedded in syslog
        idx = s.find("CEF:")
        if idx > 0:
            s = s[idx:]

        # Split on unescaped pipe
        # We need at least 7 pipes to have 8 segments
        parts = re.split(r'(?<!\\)\|', s)
        if len(parts) < 8:
            return IntermediateParseResult(
                success=False,
                format_name="CEF",
                raw_log=raw_log,
                warnings=[f"CEF header has {len(parts)} segments, expected at least 8"],
                error_codes=["ERR_MALFORMED_CEF_HEADER"],
                is_exact_syntax=False,
                parser_name=self.name
            )

        cef_version = parts[0].replace("CEF:", "")
        device_vendor = parts[1].replace(r"\|", "|")
        device_product = parts[2].replace(r"\|", "|")
        device_version = parts[3].replace(r"\|", "|")
        device_event_class_id = parts[4].replace(r"\|", "|")
        name = parts[5].replace(r"\|", "|")
        severity = parts[6].replace(r"\|", "|")
        extension_str = "|".join(parts[7:])  # remainder is extension

        extracted: Dict[str, Any] = {
            "cef_version": cef_version,
            "device_vendor": device_vendor,
            "device_product": device_product,
            "device_version": device_version,
            "signature_id": device_event_class_id,
            "event_name": name,
            "severity": severity,
        }

        # Parse extension key-values
        matches = self.KV_REGEX.findall(extension_str)
        for k, quoted_v, unquoted_v in matches:
            val = quoted_v if quoted_v else unquoted_v
            # Clean escaped characters
            val_clean = val.replace(r"\=", "=").replace(r"\|", "|").replace(r"\\", "\\").replace(r"\n", "\n")
            extracted[k] = val_clean

        # Check for standard CEF timestamp tokens (rt = receiptTime, end = endTime, start = startTime)
        timestamp_raw = extracted.get("rt") or extracted.get("end") or extracted.get("start")

        return IntermediateParseResult(
            success=True,
            format_name="CEF",
            extracted_fields=extracted,
            timestamp_raw=timestamp_raw,
            raw_log=raw_log,
            warnings=warnings,
            error_codes=error_codes,
            is_exact_syntax=True,
            parser_name=self.name
        )

