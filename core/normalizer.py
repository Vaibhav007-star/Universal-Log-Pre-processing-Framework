"""
Normalization Engine for Timestamps, Network Entities, and Delimiters.
Converts heterogeneous values to standard canonical representations.
"""

import re
import ipaddress
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List
from dateutil import parser as date_parser

# Precompiled regex patterns for fast timestamp recognition
EPOCH_PATTERN = re.compile(r"^\d{10}(?:\.\d{1,6})?$")
EPOCH_MS_PATTERN = re.compile(r"^\d{13}$")
EPOCH_US_PATTERN = re.compile(r"^\d{16}$")
ISO_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$")
SYSLOG_BSD_REGEX = re.compile(r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
APACHE_DATE_REGEX = re.compile(r"^\d{1,2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}")


class Normalizer:
    """
    Standardizes timestamps, IP addresses, ports, and network directions.
    """

    @staticmethod
    def parse_timestamp(raw_val: Any) -> Tuple[str, int, str, bool]:
        """
        Parses raw timestamp into:
        (iso_utc_string, epoch_microseconds, timezone_str, is_success)
        """
        now = datetime.now(timezone.utc)
        default_iso = now.isoformat()
        default_epoch_us = int(now.timestamp() * 1_000_000)

        if raw_val is None:
            return default_iso, default_epoch_us, "UTC", False

        raw_str = str(raw_val).strip().strip("[]\"'")
        if not raw_str:
            return default_iso, default_epoch_us, "UTC", False

        # 1. Numeric Epoch seconds / milliseconds / microseconds
        try:
            if EPOCH_PATTERN.match(raw_str):
                sec = float(raw_str)
                dt = datetime.fromtimestamp(sec, tz=timezone.utc)
                return dt.isoformat(), int(sec * 1_000_000), "UTC", True
            elif EPOCH_MS_PATTERN.match(raw_str):
                ms = int(raw_str)
                dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
                return dt.isoformat(), ms * 1000, "UTC", True
            elif EPOCH_US_PATTERN.match(raw_str):
                us = int(raw_str)
                dt = datetime.fromtimestamp(us / 1_000_000.0, tz=timezone.utc)
                return dt.isoformat(), us, "UTC", True
        except (ValueError, OverflowError, OSError):
            pass

        # 2. Apache style: 10/Oct/2026:13:55:36 +0530
        if APACHE_DATE_REGEX.match(raw_str):
            try:
                dt = datetime.strptime(raw_str, "%d/%b/%Y:%H:%M:%S %z")
                dt_utc = dt.astimezone(timezone.utc)
                return dt_utc.isoformat(), int(dt_utc.timestamp() * 1_000_000), str(dt.tzinfo), True
            except ValueError:
                pass

        # 3. Syslog BSD style (missing year): Sep 16 17:15:00
        if SYSLOG_BSD_REGEX.match(raw_str):
            try:
                current_year = now.year
                augmented = f"{current_year} {raw_str}"
                dt = datetime.strptime(augmented, "%Y %b %d %H:%M:%S")
                dt_utc = dt.replace(tzinfo=timezone.utc)
                return dt_utc.isoformat(), int(dt_utc.timestamp() * 1_000_000), "UTC", True
            except ValueError:
                pass

        # 4. General Dateutil parsing with timezone awareness
        try:
            dt = date_parser.parse(raw_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat(), int(dt.timestamp() * 1_000_000), str(dt.tzinfo or "UTC"), True
        except Exception:
            return default_iso, default_epoch_us, "UTC", False

    @staticmethod
    def classify_ip(ip_str: Optional[str]) -> Tuple[Optional[str], Optional[bool], Optional[str]]:
        """
        Validates IP and determines RFC1918 private status and IP version.
        Returns (clean_ip, is_private, version)
        """
        if not ip_str:
            return None, None, None

        clean = str(ip_str).strip().strip("[]\"'")
        # Strip port if present in IPv4 (e.g. 192.168.1.1:8080)
        if ":" in clean and "." in clean and not clean.startswith("["):
            parts = clean.split(":")
            if len(parts) == 2:
                clean = parts[0]

        try:
            ip_obj = ipaddress.ip_address(clean)
            return clean, ip_obj.is_private, f"IPv{ip_obj.version}"
        except ValueError:
            return None, None, None

    @staticmethod
    def determine_direction(
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_is_private: Optional[bool],
        dst_is_private: Optional[bool]
    ) -> str:
        """
        Infers traffic direction from endpoint classifications:
        - Inbound: Public -> Private
        - Outbound: Private -> Public
        - Internal: Private -> Private
        - External: Public -> Public
        """
        if src_is_private is True and dst_is_private is False:
            return "outbound"
        elif src_is_private is False and dst_is_private is True:
            return "inbound"
        elif src_is_private is True and dst_is_private is True:
            return "internal"
        elif src_is_private is False and dst_is_private is False:
            return "external"
        return "unknown"

    @staticmethod
    def normalize_action(action_raw: Optional[str]) -> str:
        """
        Maps varied action terms to OCSF EventAction values.
        """
        if not action_raw:
            return "unknown"

        s = str(action_raw).strip().lower()
        if any(x in s for x in ("allow", "permit", "accept", "pass", "granted")):
            return "allow"
        elif any(x in s for x in ("deny", "block", "reject", "refused", "prevented")):
            return "deny"
        elif any(x in s for x in ("drop", "discard")):
            return "drop"
        elif any(x in s for x in ("alert", "alarm", "warn")):
            return "alert"
        elif any(x in s for x in ("log", "info", "notice")):
            return "log"
        elif any(x in s for x in ("modify", "update", "change", "write")):
            return "modify"
        return "unknown"

    @staticmethod
    def normalize_severity(severity_raw: Optional[str]) -> str:
        """
        Maps numerical or text severity to standard OCSF EventSeverity.
        """
        if not severity_raw:
            return "info"

        s = str(severity_raw).strip().lower()
        if s in ("0", "emerg", "emergency", "fatal"):
            return "emergency"
        elif s in ("1", "alert"):
            return "alert"
        elif s in ("2", "crit", "critical"):
            return "critical"
        elif s in ("3", "err", "error", "fail", "failure"):
            return "error"
        elif s in ("4", "warn", "warning"):
            return "warning"
        elif s in ("5", "notice"):
            return "notice"
        elif s in ("6", "info", "informational"):
            return "info"
        elif s in ("7", "debug", "trace"):
            return "debug"
        return "info"

