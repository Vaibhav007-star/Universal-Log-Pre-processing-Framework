"""
Linux Auditd Deterministic Parser.
Parses system audit logs (type=SYSCALL, type=EXECVE, type=USER_AUTH, etc.).
"""

import re
from typing import Tuple, Dict, Any
from parsers.base import BaseParser, IntermediateParseResult


class AuditdParser(BaseParser):
    name = "auditd_deterministic"
    priority = 75
    supported_formats = ["AUDITD"]

    # Match type=... and msg=audit(epoch.ms:id):
    AUDIT_HEADER_REGEX = re.compile(
        r"^type=(?P<type>[A-Z0-9_]+)\s+msg=audit\((?P<timestamp>\d+\.\d+):(?P<audit_id>\d+)\):\s*(?P<body>.*)$"
    )
    KV_REGEX = re.compile(r'([a-zA-Z0-9_\-\.]+)=(?:"([^"]*)"|(\S+))')

    def can_parse(self, raw_log: str) -> Tuple[bool, float]:
        s = raw_log.strip()
        if s.startswith("type=") and "msg=audit(" in s:
            return True, 0.96
        return False, 0.0

    def parse(self, raw_log: str) -> IntermediateParseResult:
        s = raw_log.strip()
        m = self.AUDIT_HEADER_REGEX.match(s)
        if not m:
            # Fallback to key-value if type= was present but format slightly altered
            return IntermediateParseResult(
                success=False,
                format_name="AUDITD",
                raw_log=raw_log,
                error_codes=["ERR_AUDITD_HEADER_MISMATCH"],
                is_exact_syntax=False,
                parser_name=self.name
            )

        audit_type = m.group("type")
        timestamp_raw = m.group("timestamp")
        audit_id = m.group("audit_id")
        body = m.group("body")

        extracted: Dict[str, Any] = {
            "audit_type": audit_type,
            "audit_id": audit_id,
            "event_time_epoch": timestamp_raw,
        }

        # Parse key-values in body
        for k, quoted_v, unquoted_v in self.KV_REGEX.findall(body):
            val = quoted_v if quoted_v else unquoted_v
            extracted[k] = val

        # Map common auditd fields
        if "comm" in extracted:
            extracted["process_name"] = extracted["comm"]
        if "exe" in extracted:
            extracted["executable_path"] = extracted["exe"]
        if "pid" in extracted:
            try:
                extracted["pid"] = int(extracted["pid"])
            except ValueError:
                pass
        if "success" in extracted:
            extracted["status"] = "success" if extracted["success"].lower() in ("yes", "1") else "failure"

        return IntermediateParseResult(
            success=True,
            format_name="AUDITD",
            extracted_fields=extracted,
            timestamp_raw=timestamp_raw,
            raw_log=raw_log,
            is_exact_syntax=True,
            parser_name=self.name
        )
