"""
Multi-Level Confidence Scoring Engine for Log Processing.
Calculates independent scores for:
1. Format Detection Confidence
2. Field Extraction Confidence
3. Schema Mapping Confidence
4. Overall Composite Confidence
"""

import ipaddress
from typing import Dict, Any, List, Optional
from core.schema import ConfidenceBreakdown, EventCategory, EventAction


class ConfidenceScorer:
    """
    Evaluates extraction quality and produces calibrated confidence metrics.
    """

    @staticmethod
    def calculate_format_confidence(format_detected: str, parser_used: str, is_exact_syntax: bool = True) -> float:
        """
        Confidence in format detection (0.0 to 1.0).
        """
        fmt = format_detected.upper()
        if fmt == "JSON":
            return 1.0 if is_exact_syntax else 0.8
        elif fmt in ("CEF", "LEEF"):
            return 0.98 if is_exact_syntax else 0.75
        elif "SYSLOG" in fmt:
            return 0.95 if is_exact_syntax else 0.70
        elif fmt == "AUDITD":
            return 0.92 if is_exact_syntax else 0.70
        elif fmt == "KEY_VALUE":
            return 0.85
        elif fmt == "JIT_INFERRED":
            return 0.80
        elif fmt == "GENERIC_FALLBACK":
            return 0.35
        return 0.20

    @staticmethod
    def calculate_field_extraction_confidence(
        extracted_fields: Dict[str, Any],
        warnings: List[str]
    ) -> float:
        """
        Evaluates physical validity of extracted fields (IPs, ports, timestamps).
        """
        if not extracted_fields:
            return 0.1

        score = 0.0
        checks_performed = 0

        # Check IP validity across standard and vendor keys
        ip_keys = (
            "src_ip", "dst_ip", "src", "dst", "client_ip", "server_ip",
            "ip", "src_endpoint_ip", "dst_endpoint_ip", "c_ip", "s_ip", "d_ip"
        )
        for key in ip_keys:
            val = extracted_fields.get(key)
            if val and isinstance(val, str):
                checks_performed += 1
                clean_ip = val.strip().strip("[]\"'")
                if ":" in clean_ip and "." in clean_ip and not clean_ip.startswith("["):
                    clean_ip = clean_ip.split(":")[0]
                if "/" in clean_ip:
                    clean_ip = clean_ip.split("/")[0]
                try:
                    ipaddress.ip_address(clean_ip)
                    score += 1.0
                except ValueError:
                    warnings.append(f"Invalid IP address format: {val}")
                    score += 0.0

        # Check Port validity
        port_keys = (
            "src_port", "dst_port", "spt", "dpt", "port", "dstPort", "srcPort",
            "src_endpoint_port", "dst_endpoint_port"
        )
        for key in port_keys:
            val = extracted_fields.get(key)
            if val is not None:
                checks_performed += 1
                try:
                    p = int(str(val).split("/")[0])
                    if 1 <= p <= 65535:
                        score += 1.0
                    else:
                        warnings.append(f"Port number out of valid range (1-65535): {p}")
                        score += 0.2
                except (ValueError, TypeError):
                    warnings.append(f"Non-integer port value: {val}")
                    score += 0.0

        # Check Timestamp presence and quality
        timestamp_keys = (
            "timestamp", "time", "date", "@timestamp", "event_time",
            "rt", "devTime", "calmTime", "start", "end", "datetime"
        )
        has_ts = any(k in extracted_fields and extracted_fields[k] for k in timestamp_keys)
        checks_performed += 1
        if has_ts:
            score += 1.0
        else:
            warnings.append("No explicit timestamp token found in raw payload")
            score += 0.3

        if checks_performed == 0:
            return 0.5

        return min(1.0, max(0.0, score / checks_performed))

    @staticmethod
    def calculate_schema_mapping_confidence(
        mapped_record: Dict[str, Any],
        has_directional_ambiguity: bool = False,
        warnings: Optional[List[str]] = None
    ) -> float:
        """
        Evaluates how completely and unambiguously raw fields map into OCSF standard schema.
        """
        if warnings is None:
            warnings = []

        score = 0.0

        # Timestamp normalized successfully
        ts = mapped_record.get("timestamp", {})
        if ts.get("raw") and ts.get("normalized"):
            score += 0.25
        elif ts.get("normalized"):
            score += 0.10

        # Event classification
        ev = mapped_record.get("event", {})
        if ev.get("category") and ev.get("category") != EventCategory.UNKNOWN.value:
            score += 0.20
        if ev.get("action") and ev.get("action") != EventAction.UNKNOWN.value:
            score += 0.15

        # Endpoints mapped
        src = mapped_record.get("src_endpoint", {})
        dst = mapped_record.get("dst_endpoint", {})
        has_src = bool(src.get("ip") or src.get("domain"))
        has_dst = bool(dst.get("ip") or dst.get("domain"))

        if has_src and has_dst:
            score += 0.25
        elif has_src or has_dst:
            score += 0.15

        # Device or process info
        dev = mapped_record.get("device", {})
        proc = mapped_record.get("process", {})
        act = mapped_record.get("actor", {})
        if dev.get("hostname") or dev.get("vendor") or proc.get("name") or act.get("user_name"):
            score += 0.15

        # Penalize directional ambiguity
        if has_directional_ambiguity:
            warnings.append("Ambiguous network direction: source and destination inferred by heuristic")
            score = max(0.2, score - 0.20)

        return min(1.0, max(0.1, score))

    @classmethod
    def compute_composite_confidence(
        cls,
        format_detected: str,
        parser_used: str,
        is_exact_syntax: bool,
        extracted_fields: Dict[str, Any],
        mapped_record: Dict[str, Any],
        has_directional_ambiguity: bool = False,
        warnings: Optional[List[str]] = None
    ) -> ConfidenceBreakdown:
        """
        Generates unified ConfidenceBreakdown object.
        """
        if warnings is None:
            warnings = []

        fmt_conf = cls.calculate_format_confidence(format_detected, parser_used, is_exact_syntax)
        field_conf = cls.calculate_field_extraction_confidence(extracted_fields, warnings)
        schema_conf = cls.calculate_schema_mapping_confidence(mapped_record, has_directional_ambiguity, warnings)

        overall = (0.25 * fmt_conf) + (0.35 * field_conf) + (0.40 * schema_conf)

        return ConfidenceBreakdown(
            format_confidence=round(fmt_conf, 3),
            field_extraction_confidence=round(field_conf, 3),
            schema_mapping_confidence=round(schema_conf, 3),
            overall_confidence=round(overall, 3)
        )
