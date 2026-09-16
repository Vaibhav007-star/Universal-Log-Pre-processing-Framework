"""
Syslog Deterministic Parser.
Supports RFC 5424 (Modern standard), RFC 3164 (BSD Syslog), and Cisco ASA/Network Syslog headers.
"""

import re
from typing import Tuple, Dict, Any, Optional
from parsers.base import BaseParser, IntermediateParseResult


class SyslogParser(BaseParser):
    name = "syslog_deterministic"
    priority = 80
    supported_formats = ["SYSLOG_RFC5424", "SYSLOG_RFC3164"]

    # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
    RFC5424_REGEX = re.compile(
        r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
        r"(?P<appname>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s*(?P<rest>.*)$"
    )

    # RFC 3164: <PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG
    RFC3164_REGEX = re.compile(
        r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+(?P<tag>[a-zA-Z0-9_\-\./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
    )

    # Cisco ASA / Network Syslog without standard PRI or with embedded PRI:
    # <166>%ASA-4-106023: Deny tcp src outside:198.51.100.4/44321 dst inside:10.1.1.50/80
    CISCO_REGEX = re.compile(
        r"^(?:<(?P<pri>\d{1,3})>)?%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<msg>.*)$"
    )

    def can_parse(self, raw_log: str) -> Tuple[bool, float]:
        s = raw_log.strip()
        if s.startswith("<") and ">" in s[:5]:
            return True, 0.95
        if s.startswith("%") and ":" in s:
            return True, 0.90
        # RFC 3164 without PRI header: Sep 16 17:15:00 host app: msg
        if re.match(r"^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+.*:", s):
            return True, 0.85
        return False, 0.0

    @staticmethod
    def _parse_pri(pri_int: int) -> Tuple[int, int]:
        """Facility = pri // 8, Severity = pri % 8"""
        facility = pri_int // 8
        severity = pri_int % 8
        return facility, severity

    def parse(self, raw_log: str) -> IntermediateParseResult:
        s = raw_log.strip()
        extracted: Dict[str, Any] = {}
        timestamp_raw = None
        format_name = "SYSLOG"

        # 1. Try RFC 5424
        m5424 = self.RFC5424_REGEX.match(s)
        if m5424:
            format_name = "SYSLOG_RFC5424"
            pri = int(m5424.group("pri"))
            fac, sev = self._parse_pri(pri)
            extracted.update({
                "syslog_pri": pri,
                "syslog_facility": fac,
                "syslog_severity": sev,
                "syslog_version": m5424.group("version"),
                "hostname": m5424.group("hostname"),
                "app_name": m5424.group("appname"),
                "procid": m5424.group("procid"),
                "msgid": m5424.group("msgid"),
            })
            timestamp_raw = m5424.group("timestamp")
            rest = m5424.group("rest")
            # Parse structured data [id key="val"] if present
            extracted["message"] = rest

            return IntermediateParseResult(
                success=True,
                format_name=format_name,
                extracted_fields=extracted,
                timestamp_raw=timestamp_raw,
                raw_log=raw_log,
                is_exact_syntax=True,
                parser_name=self.name
            )

        # 2. Try RFC 3164
        m3164 = self.RFC3164_REGEX.match(s)
        if m3164:
            format_name = "SYSLOG_RFC3164"
            pri = int(m3164.group("pri"))
            fac, sev = self._parse_pri(pri)
            extracted.update({
                "syslog_pri": pri,
                "syslog_facility": fac,
                "syslog_severity": sev,
                "hostname": m3164.group("hostname"),
                "app_name": m3164.group("tag"),
                "pid": m3164.group("pid"),
                "message": m3164.group("msg"),
            })
            timestamp_raw = m3164.group("timestamp")

            return IntermediateParseResult(
                success=True,
                format_name=format_name,
                extracted_fields=extracted,
                timestamp_raw=timestamp_raw,
                raw_log=raw_log,
                is_exact_syntax=True,
                parser_name=self.name
            )

        # 3. Try Cisco style
        mcisco = self.CISCO_REGEX.match(s)
        if mcisco:
            format_name = "SYSLOG_CISCO"
            pri_val = mcisco.group("pri")
            if pri_val:
                fac, sev = self._parse_pri(int(pri_val))
                extracted["syslog_pri"] = int(pri_val)
                extracted["syslog_facility"] = fac
                extracted["syslog_severity"] = sev
            else:
                extracted["syslog_severity"] = int(mcisco.group("severity"))

            msg_text = mcisco.group("msg")
            extracted.update({
                "facility": mcisco.group("facility"),
                "mnemonic": mcisco.group("mnemonic"),
                "message": msg_text,
            })

            # Extract Cisco ASA network tokens if present
            cisco_payload_m = re.search(
                r'(?P<action>Deny|Built|Teardown|Permit|Allow|Drop)\s+(?P<proto>\w+)\s+src\s+(?:(?P<src_if>\w+):)?(?P<src>[^/:\s]+)(?:/(?P<spt>\d+))?\s+dst\s+(?:(?P<dst_if>\w+):)?(?P<dst>[^/:\s]+)(?:/(?P<dpt>\d+))?',
                msg_text,
                re.IGNORECASE
            )
            if cisco_payload_m:
                for k, v in cisco_payload_m.groupdict().items():
                    if v:
                        extracted[k] = v

            return IntermediateParseResult(
                success=True,
                format_name=format_name,
                extracted_fields=extracted,
                timestamp_raw=None,
                raw_log=raw_log,
                is_exact_syntax=True,
                parser_name=self.name
            )

        return IntermediateParseResult(
            success=False,
            format_name="SYSLOG",
            raw_log=raw_log,
            error_codes=["ERR_UNRECOGNIZED_SYSLOG_PATTERN"],
            is_exact_syntax=False,
            parser_name=self.name
        )
