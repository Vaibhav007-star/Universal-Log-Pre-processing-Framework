"""
Tests for Deterministic and Fallback Log Parsers.
"""

from parsers.deterministic.json_parser import JSONFastParser
from parsers.deterministic.cef_parser import CEFParser
from parsers.deterministic.leef_parser import LEEFParser
from parsers.deterministic.syslog_parser import SyslogParser
from parsers.deterministic.auditd_parser import AuditdParser
from parsers.deterministic.keyvalue_parser import KeyValueParser
from parsers.fallback.generic_extractor import GenericFallbackExtractor


def test_json_parser():
    p = JSONFastParser()
    raw = '{"timestamp": "2026-09-16T10:00:00Z", "actor": {"user": "admin"}, "network": {"src_ip": "10.0.0.1"}}'
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True
    assert conf >= 0.90

    res = p.parse(raw)
    assert res.success is True
    assert res.extracted_fields["network.src_ip"] == "10.0.0.1"
    assert res.extracted_fields["actor.user"] == "admin"
    assert res.timestamp_raw == "2026-09-16T10:00:00Z"


def test_cef_parser():
    p = CEFParser()
    raw = 'CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|drop|Drop|4|src=192.168.1.50 dst=10.0.0.1 spt=44321 dpt=443 proto=tcp act=drop'
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True
    assert conf >= 0.95

    res = p.parse(raw)
    assert res.success is True
    assert res.extracted_fields["src"] == "192.168.1.50"
    assert res.extracted_fields["dst"] == "10.0.0.1"
    assert res.extracted_fields["dpt"] == "443"
    assert res.extracted_fields["device_vendor"] == "Check Point"


def test_leef_parser():
    p = LEEFParser()
    raw = "LEEF:2.0|Microsoft|MSExchange|4.0|15345|\tdevTime=2026-09-16T12:00:00Z\tsrc=10.10.1.25\tdst=10.10.2.50\taccount=jdoe"
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True

    res = p.parse(raw)
    assert res.success is True
    assert res.extracted_fields["src"] == "10.10.1.25"
    assert res.extracted_fields["account"] == "jdoe"


def test_syslog_rfc5424():
    p = SyslogParser()
    raw = '<165>1 2026-09-16T17:15:00.003Z border-gw firewall 4124 ID47 [exampleSDID@32473 iut="3"] User login initiated'
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True

    res = p.parse(raw)
    assert res.success is True
    assert res.extracted_fields["hostname"] == "border-gw"
    assert res.extracted_fields["app_name"] == "firewall"
    assert res.extracted_fields["procid"] == "4124"
    assert res.timestamp_raw == "2026-09-16T17:15:00.003Z"


def test_syslog_cisco():
    p = SyslogParser()
    raw = "%ASA-4-106023: Deny tcp src outside:198.51.100.4/44321 dst inside:10.1.1.50/80 by access-group 'DMZ_IN'"
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True

    res = p.parse(raw)
    assert res.success is True
    assert res.extracted_fields["facility"] == "ASA"
    assert res.extracted_fields["mnemonic"] == "106023"


def test_auditd_parser():
    p = AuditdParser()
    raw = 'type=SYSCALL msg=audit(1726485002.124:942): arch=c000003e syscall=59 success=yes pid=4124 comm="nc" exe="/usr/bin/ncat"'
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True

    res = p.parse(raw)
    assert res.success is True
    assert res.extracted_fields["audit_type"] == "SYSCALL"
    assert res.extracted_fields["comm"] == "nc"
    assert res.extracted_fields["pid"] == 4124
    assert res.extracted_fields["status"] == "success"


def test_keyvalue_parser():
    p = KeyValueParser()
    raw = 'user="analyst1" src_ip=192.168.1.99 dst_ip=10.0.0.50 action="permit" proto="tcp"'
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True

    res = p.parse(raw)
    assert res.success is True
    assert res.extracted_fields["user"] == "analyst1"
    assert res.extracted_fields["src_ip"] == "192.168.1.99"
    assert res.extracted_fields["action"] == "permit"


def test_generic_fallback_extractor():
    p = GenericFallbackExtractor()
    raw = 'Critical connection drop from 203.0.113.19 port 5353 to 198.51.100.25 at 2026-09-16T14:30:00Z code 0x8FA4'
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True

    res = p.parse(raw)
    assert res.success is True
    assert res.extracted_fields["src_ip"] == "203.0.113.19"
    assert res.extracted_fields["dst_ip"] == "198.51.100.25"
    assert res.extracted_fields["dst_port"] == 5353
    assert "0x8FA4" in res.extracted_fields["hex_codes"]
    assert res.extracted_fields["action"] == "deny"

