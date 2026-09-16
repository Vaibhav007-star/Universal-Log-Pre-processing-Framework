"""
Tests for Extreme Edge Cases, Malformed Logs, and Graceful Degradation.
Addresses Requirement 8 & 9:
- Malformed logs, missing fields, duplicate events, multiline logs
- Timestamps in different formats, invalid IP addresses, unusual delimiters, escaped characters, partially corrupted records
- Never silently discard logs; preserve raw log, return partial structured fields + error codes.
"""

from core.pipeline import UniversalLogPipeline
from core.schema import EventAction, EventStatus
from core.normalizer import Normalizer


def test_malformed_json_partial_recovery():
    pipeline = UniversalLogPipeline(enable_duckdb=False, enable_dead_letter=False)
    # JSON with syntax error (missing quote, trailing comma, unclosed bracket)
    malformed_json = '{"src_ip": "192.168.1.100", "action": "blocked", "port": 80, "unclosed": }'
    rec = pipeline.process_log(malformed_json)

    # Must NOT raise unhandled exception, must NOT discard
    assert rec.raw_log == malformed_json
    # Generic fallback or partial extraction should still rescue the IP and action!
    assert rec.src_endpoint.ip == "192.168.1.100"
    assert rec.event.action == EventAction.DENY
    assert "ERR_MALFORMED_JSON" in rec.processing_metadata.error_codes or "WARN_GENERIC_FALLBACK_APPLIED" in rec.processing_metadata.error_codes


def test_invalid_ip_addresses_are_warned_not_crashed():
    pipeline = UniversalLogPipeline(enable_duckdb=False, enable_dead_letter=False)
    log_with_invalid_ip = 'CEF:0|Vendor|Product|1.0|100|Event|3|src=999.999.999.999 dst=10.0.0.1 act=allow'
    rec = pipeline.process_log(log_with_invalid_ip)

    assert rec.raw_log == log_with_invalid_ip
    # dst should be parsed because it is valid
    assert rec.dst_endpoint.ip == "10.0.0.1"
    # src was invalid so it should be None, and a warning should be recorded
    assert rec.src_endpoint.ip is None
    assert any("Invalid" in w or "Malformed" in w for w in rec.processing_metadata.warnings)
    assert any("ERR_INVALID_SRC_IP" in err for err in rec.processing_metadata.error_codes)


def test_unusual_delimiters_and_escaped_characters():
    pipeline = UniversalLogPipeline(enable_duckdb=False, enable_dead_letter=False)
    # Escaped quotes, equals inside values, mixed delimiters
    escaped_log = 'CEF:0|Vendor|Product|1.0|100|Event|3|cs1=Value\\=With\\=Equals cs2=Pipe\\|Separated src=172.16.0.4'
    rec = pipeline.process_log(escaped_log)

    assert rec.src_endpoint.ip == "172.16.0.4"
    assert rec.src_endpoint.is_private is True
    # Check escaped fields are cleanly unescaped in unmapped
    assert rec.unmapped.get("cs1") == "Value=With=Equals"
    assert rec.unmapped.get("cs2") == "Pipe|Separated"


def test_missing_fields_defaults_gracefully():
    pipeline = UniversalLogPipeline(enable_duckdb=False, enable_dead_letter=False)
    # Extremely sparse log
    sparse_log = "Just a random status message from node 5 without any timestamps or IPs"
    rec = pipeline.process_log(sparse_log)

    assert rec.raw_log == sparse_log
    # Defaults must be populated gracefully without crash
    assert rec.event.id is not None
    assert rec.timestamp.normalized is not None
    assert rec.src_endpoint.ip is None
    assert rec.dst_endpoint.ip is None
    assert rec.processing_metadata.confidence.overall_confidence <= 0.60


def test_partially_corrupted_record_preservation():
    pipeline = UniversalLogPipeline(enable_duckdb=False, enable_dead_letter=False)
    corrupted_stream = "\x00\x00\x01\xFF %ASA-4-106023: Deny tcp src 10.1.1.1/1000 dst 10.2.2.2/80 \x00\x1B"
    rec = pipeline.process_log(corrupted_stream)

    assert rec.raw_log == corrupted_stream
    # Should still extract IPs and action
    assert rec.src_endpoint.ip == "10.1.1.1" or rec.dst_endpoint.ip == "10.2.2.2"
    assert rec.event.action == EventAction.DENY

