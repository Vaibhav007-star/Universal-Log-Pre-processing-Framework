"""
Generic Fallback Extractor for Unrecognized, Malformed, or Partial Logs.
Guarantees zero log loss by extracting all recognized atomic tokens and preserving the raw log.
"""

import re
from typing import Tuple, Dict, Any, List
from parsers.base import BaseParser, IntermediateParseResult


class GenericFallbackExtractor(BaseParser):
    name = "generic_fallback"
    priority = 1  # Lowest priority: executed only when all other parsers fail
    supported_formats = ["UNSTRUCTURED_GENERIC"]

    IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    MAC_REGEX = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b')
    PORT_REGEX = re.compile(r'\b(?:port|sport|dport|spt|dpt|pt)[\s:=]+(\d{1,5})\b', re.IGNORECASE)
    TIMESTAMP_REGEX = re.compile(r'\b(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b')
    HEX_REGEX = re.compile(r'\b0x[0-9a-fA-F]+\b')
    USER_REGEX = re.compile(r'\b(?:user|username|usr|account|for)\s*[=:]\s*[\'"]?([a-zA-Z0-9_\-\.\@]+)[\'"]?', re.IGNORECASE)

    def can_parse(self, raw_log: str) -> Tuple[bool, float]:
        # Always can parse as last resort
        return True, 0.35

    def parse(self, raw_log: str) -> IntermediateParseResult:
        s = raw_log.strip()
        extracted: Dict[str, Any] = {}
        warnings: List[str] = ["Parsed using generic fallback token extraction"]
        error_codes: List[str] = ["WARN_GENERIC_FALLBACK_APPLIED"]

        # 1. Extract IPs
        ips = self.IPV4_REGEX.findall(s)
        if ips:
            extracted["detected_ips"] = ips
            if len(ips) == 1:
                # Single IP: context check
                if any(w in s.lower() for w in ("from", "src", "client", "host")):
                    extracted["src_ip"] = ips[0]
                else:
                    extracted["ip"] = ips[0]
            elif len(ips) >= 2:
                # Multiple IPs: assign first as src, second as dst
                extracted["src_ip"] = ips[0]
                extracted["dst_ip"] = ips[1]
                warnings.append("Inferred source and destination IPs positionally from unstructured text")

        # 2. Extract Timestamp
        ts_match = self.TIMESTAMP_REGEX.search(s)
        timestamp_raw = ts_match.group(0) if ts_match else None

        # 3. Extract Ports
        ports = self.PORT_REGEX.findall(s)
        if ports:
            extracted["detected_ports"] = [int(p) for p in ports if 1 <= int(p) <= 65535]
            if extracted["detected_ports"]:
                extracted["dst_port"] = extracted["detected_ports"][0]

        # 4. Extract MAC addresses
        macs = self.MAC_REGEX.findall(s)
        if macs:
            extracted["detected_macs"] = macs

        # 5. Extract Hex codes (error codes or memory addresses)
        hex_codes = self.HEX_REGEX.findall(s)
        if hex_codes:
            extracted["hex_codes"] = hex_codes

        # 6. Extract User
        user_match = self.USER_REGEX.search(s)
        if user_match:
            extracted["user_name"] = user_match.group(1)

        # 7. Action keyword inference
        lower_s = s.lower()
        if any(w in lower_s for w in ("deny", "blocked", "drop", "reject", "failed")):
            extracted["action"] = "deny"
        elif any(w in lower_s for w in ("allow", "accept", "permit", "success")):
            extracted["action"] = "allow"

        return IntermediateParseResult(
            success=True,
            format_name="GENERIC_FALLBACK",
            extracted_fields=extracted,
            timestamp_raw=timestamp_raw,
            raw_log=raw_log,
            warnings=warnings,
            error_codes=error_codes,
            is_exact_syntax=False,
            parser_name=self.name
        )

