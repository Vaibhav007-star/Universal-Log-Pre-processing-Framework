"""
End-to-End Pipeline Integration Tests.
"""

from core.pipeline import UniversalLogPipeline
from core.schema import EventAction, EventCategory


def test_pipeline_json_normalization():
    pipeline = UniversalLogPipeline(enable_duckdb=False, enable_dead_letter=False)
    log = '{"time": "2026-09-16T12:00:00Z", "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "dst_port": 53, "action": "allow"}'
    rec = pipeline.process_log(log)

    assert rec.processing_metadata.format_detected == "JSON"
    assert rec.processing_metadata.parser_used == "json_fast"
    assert rec.src_endpoint.ip == "192.168.1.10"
    assert rec.src_endpoint.is_private is True
    assert rec.dst_endpoint.ip == "8.8.8.8"
    assert rec.dst_endpoint.is_private is False
    assert rec.network.direction == "outbound"
    assert rec.dst_endpoint.port == 53
    assert rec.event.action == EventAction.ALLOW
    assert rec.processing_metadata.confidence.overall_confidence >= 0.85
    assert rec.raw_log == log


def test_pipeline_novel_unseen_format_cold_path():
    pipeline = UniversalLogPipeline(enable_duckdb=False, enable_dead_letter=False)
    # Novel defense sensor log never explicitly written into deterministic plugins
    novel_log = "[RADAR-SIG-V4] 2026-09-16T17:01:22Z | NODE=BORDER_NORTH | STATUS=TRACKING | TARGET=UNKNOWN | MSG=active"
    rec = pipeline.process_log(novel_log)

    assert rec.raw_log == novel_log
    # Either synthesized dynamically or processed cleanly via fallback/JIT
    assert rec.processing_metadata.confidence.overall_confidence > 0.30
    assert rec.timestamp.normalized is not None


def test_pipeline_preserves_raw_on_corrupted_log():
    pipeline = UniversalLogPipeline(enable_duckdb=False, enable_dead_letter=False)
    corrupted = "CORRUPTED_HEX_GARBAGE_\x00\x01\x02_ERROR_404_IP=999.999.999.999_TIME=INVALID_DATE"
    rec = pipeline.process_log(corrupted)

    # Never silently drop!
    assert rec.raw_log == corrupted
    # Error codes and warnings populated
    assert len(rec.processing_metadata.warnings) > 0 or len(rec.processing_metadata.error_codes) > 0

