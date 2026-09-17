"""
Universal Log Pre-processing Pipeline Orchestrator.
Implements the Deterministic-First, Dual-Engine Architecture:
  1. Deterministic Fast-Path Plugins (JSON, CEF, LEEF, Syslog, Auditd, Key-Value)
  2. Dynamic Rule Cache (Persistent SQLite JIT Parsers)
  3. Novel Unknown Format -> Cold-Path JIT Synthesis (Drain3 + RuleSynthesizer)
  4. Fallback -> Generic Token Extractor (Zero Silent Drops)
  5. Canonical OCSF v1.1 Normalization, Multi-Level Confidence Scoring & HITL Enqueue
"""

import time
import re
from typing import Dict, Any, List, Optional, Tuple

from core.schema import (
    CanonicalLogRecord,
    EventCategory,
    EventAction,
    EventSeverity,
    EventStatus,
    GeoLocation,
    Endpoint,
    NetworkDetails,
    DeviceDetails,
    ActorDetails,
    ProcessDetails,
    TimestampMetadata,
    ProcessingMetadata,
    ConfidenceBreakdown
)
from core.normalizer import Normalizer
from core.confidence import ConfidenceScorer
from parsers.base import BaseParser, IntermediateParseResult
from parsers.registry import ParserRegistry
from parsers.deterministic.json_parser import JSONFastParser
from parsers.deterministic.cef_parser import CEFParser
from parsers.deterministic.leef_parser import LEEFParser
from parsers.deterministic.syslog_parser import SyslogParser
from parsers.deterministic.keyvalue_parser import KeyValueParser
from parsers.deterministic.auditd_parser import AuditdParser
from parsers.fallback.generic_extractor import GenericFallbackExtractor

from inference.template_miner import LogTemplateMiner
from inference.rule_store import LearnedRuleStore, DynamicRegexParser
from inference.rule_synthesizer import RuleSynthesizer
from hitl.review_queue import ReviewQueue
from hitl.feedback_handler import FeedbackHandler
from storage.duckdb_sink import DuckDBSink
from storage.dead_letter import DeadLetterSink
import config


class UniversalLogPipeline:
    """
    High-throughput, defense-grade universal log normalization orchestrator.
    """

    def __init__(
        self,
        enable_duckdb: bool = True,
        enable_dead_letter: bool = True,
        inference_backend: str = config.INFERENCE_BACKEND
    ):
        self.registry = ParserRegistry()
        self._register_default_parsers()

        self.template_miner = LogTemplateMiner()
        self.rule_store = LearnedRuleStore(config.RULES_DB_PATH)
        self.rule_synthesizer = RuleSynthesizer(self.rule_store, backend=inference_backend)
        self.review_queue = ReviewQueue(config.REVIEW_QUEUE_DB_PATH)
        self.feedback_handler = FeedbackHandler(self.rule_store, self.registry, self.review_queue)

        # Load previously learned rules from SQLite into memory registry
        loaded_jit_count = self.rule_store.load_all_into_registry(self.registry)
        if loaded_jit_count > 0:
            print(f"[INIT] Loaded {loaded_jit_count} persistent JIT rules into parser registry")

        self.duckdb_sink = DuckDBSink(config.DUCKDB_PATH) if enable_duckdb else None
        self.dead_letter_sink = DeadLetterSink(config.DEAD_LETTER_PATH) if enable_dead_letter else None

    def _register_default_parsers(self):
        """Registers built-in deterministic parsers and the fallback extractor."""
        self.registry.register(JSONFastParser())
        self.registry.register(CEFParser())
        self.registry.register(LEEFParser())
        self.registry.register(SyslogParser())
        self.registry.register(AuditdParser())
        self.registry.register(KeyValueParser())
        self.fallback_parser = GenericFallbackExtractor()

    def process_log(self, raw_log: str) -> CanonicalLogRecord:
        """
        Processes a single raw log string through the end-to-end normalization pipeline.
        """
        start_ns = time.perf_counter_ns()
        raw_clean = raw_log.strip()

        if not raw_clean:
            # Degraded record for empty log
            rec = CanonicalLogRecord(raw_log=raw_log)
            rec.processing_metadata.warnings.append("Received empty log line")
            rec.processing_metadata.error_codes.append("ERR_EMPTY_LOG")
            return rec

        parser_used: Optional[BaseParser] = None
        parse_res: Optional[IntermediateParseResult] = None
        inference_used = False

        # =========================================================================
        # STAGE 1: THE FAST TRACK (Hot-Path Check)
        # Check if the log belongs to a known, pre-compiled format (Cisco, CEF, JSON,
        # Syslog, Auditd, KeyValue). If matched, parses deterministically in < 200 µs.
        # =========================================================================
        parser_used, parse_res = self.registry.detect_and_parse(raw_clean)

        # =========================================================================
        # STAGE 2: THE SMART LEARNER (Cold-Path JIT AI Synthesis)
        # If the log is completely new or unseen:
        #   1. Drain3 algorithm extracts the structural template (signature hash).
        #   2. Check if we already learned this signature in our SQLite rule store.
        #   3. If not, synthesize a new regular expression dynamically, sandbox it,
        #      and save it so future logs of this type run on the Fast Track!
        # =========================================================================
        if not parser_used or not parse_res or not parse_res.success:
            cluster_meta = self.template_miner.process_log(raw_clean)
            sig_id = cluster_meta["signature_hash"]
            template_str = cluster_meta["template"]

            # Check if we already have a learned rule in rule store
            existing_rule = self.rule_store.get_rule(sig_id)
            if existing_rule:
                # Instantiate and run the previously learned rule
                jit_parser = DynamicRegexParser(
                    signature_id=sig_id,
                    regex_pattern=existing_rule["regex_pattern"],
                    field_mappings=existing_rule["field_mappings"],
                    confidence_score=existing_rule["confidence_score"]
                )
                parse_res = jit_parser.parse(raw_clean)
                if parse_res.success:
                    parser_used = jit_parser
                    self.registry.register(jit_parser)
                    self.rule_store.increment_usage(sig_id)

            # If still unparsed, trigger Cold-Path JIT Synthesis
            if not parser_used or not parse_res or not parse_res.success:
                synthesized_parser, report, synth_score = self.rule_synthesizer.synthesize_rule(
                    signature_id=sig_id,
                    template_str=template_str,
                    sample_logs=[raw_clean]
                )
                if synthesized_parser:
                    parse_res = synthesized_parser.parse(raw_clean)
                    if parse_res.success:
                        parser_used = synthesized_parser
                        self.registry.register(synthesized_parser)
                        inference_used = True

        # =========================================================================
        # STAGE 3: THE SAFETY NET (Fallback Token Extractor — Zero Silent Drops)
        # If both Fast Track and AI learning cannot match, rescue every possible IP,
        # timestamp, port, and action token. The raw log is 100% preserved verbatim.
        # =========================================================================
        if not parser_used or not parse_res or not parse_res.success:
            parser_used = self.fallback_parser
            parse_res = self.fallback_parser.parse(raw_clean)

        # =========================================================================
        # STAGE 4: THE UNIVERSAL TRANSLATOR (Canonical OCSF Normalization)
        # Standardize heterogeneous fields into the international OCSF v1.1 format:
        #   - Convert all timestamp styles to standard ISO-8601 UTC
        #   - Classify IPs (Private vs Public) & determine network direction
        #   - Standardize actions (ALLOW, DENY, DROP, ALERT) & severities
        #   - Correlate suspicious activities against MITRE ATT&CK techniques
        # =========================================================================
        canonical_record = self._map_to_canonical(
            raw_clean=raw_clean,
            parse_res=parse_res,
            parser_name=parser_used.name if parser_used else "UNKNOWN",
            inference_used=inference_used,
            start_ns=start_ns
        )

        # =========================================================================
        # STAGE 5: QUALITY CHECK & PERSISTENCE ROUTING (HITL & DuckDB)
        # System calculates multi-level confidence scores (0-100%):
        #   - Score >= 60%: High confidence -> directly saved to DuckDB for analytics.
        #   - Score < 60%: Flagged -> placed in HITL review queue for 1-click analyst
        #                  correction, and recorded in Dead-Letter audit log.
        # =========================================================================
        overall_conf = canonical_record.processing_metadata.confidence.overall_confidence

        if overall_conf < config.CONFIDENCE_REVIEW_THRESHOLD:
            # Enqueue for human review in Dashboard Tab 4
            self.review_queue.enqueue(
                event_id=canonical_record.event.id,
                raw_log=raw_clean,
                format_detected=canonical_record.processing_metadata.format_detected,
                extracted_fields=parse_res.extracted_fields,
                confidence_score=overall_conf,
                confidence_breakdown=canonical_record.processing_metadata.confidence.model_dump(),
                warnings=canonical_record.processing_metadata.warnings
            )
            # Write to Dead-Letter Sink for defense forensic audits
            if self.dead_letter_sink:
                self.dead_letter_sink.write_dead_letter(
                    event_id=canonical_record.event.id,
                    raw_log=raw_clean,
                    reason_codes=canonical_record.processing_metadata.error_codes,
                    extracted_fields=parse_res.extracted_fields,
                    confidence_score=overall_conf,
                    warnings=canonical_record.processing_metadata.warnings
                )

        # Write to DuckDB embedded columnar analytical storage
        if self.duckdb_sink:
            self.duckdb_sink.insert_record(canonical_record)

        return canonical_record

    def _map_to_canonical(
        self,
        raw_clean: str,
        parse_res: IntermediateParseResult,
        parser_name: str,
        inference_used: bool,
        start_ns: int
    ) -> CanonicalLogRecord:
        """
        Maps intermediate dictionary into strict OCSF v1.1 CanonicalLogRecord.
        """
        fields = dict(parse_res.extracted_fields)
        warnings = list(parse_res.warnings)
        error_codes = list(parse_res.error_codes)

        # 1. Timestamp Normalization
        ts_raw = parse_res.timestamp_raw or fields.get("timestamp") or fields.get("time") or fields.get("date")
        iso_ts, epoch_us, tz_name, ts_ok = Normalizer.parse_timestamp(ts_raw)
        if not ts_ok and ts_raw:
            warnings.append(f"Unparseable timestamp: {ts_raw}")
            error_codes.append("ERR_UNPARSEABLE_TIMESTAMP")

        ts_meta = TimestampMetadata(
            raw=str(ts_raw) if ts_raw else None,
            normalized=iso_ts,
            epoch_us=epoch_us,
            timezone=tz_name
        )

        # 2. Endpoint & Network Mapping
        src_ip_raw = (
            fields.pop("src_endpoint.ip", None) or
            fields.pop("src_ip", None) or
            fields.pop("src", None) or
            fields.pop("c_ip", None) or
            fields.pop("client_ip", None) or
            fields.pop("s_ip", None)
        )
        dst_ip_raw = (
            fields.pop("dst_endpoint.ip", None) or
            fields.pop("dst_ip", None) or
            fields.pop("dst", None) or
            fields.pop("server_ip", None) or
            fields.pop("d_ip", None)
        )

        src_port_raw = (
            fields.pop("src_endpoint.port", None) or
            fields.pop("src_port", None) or
            fields.pop("spt", None) or
            fields.pop("sport", None)
        )
        dst_port_raw = (
            fields.pop("dst_endpoint.port", None) or
            fields.pop("dst_port", None) or
            fields.pop("dpt", None) or
            fields.pop("dport", None) or
            fields.pop("port", None)
        )

        has_directional_ambiguity = False
        if not src_ip_raw and not dst_ip_raw and "detected_ips" in fields:
            det = fields.get("detected_ips", [])
            if len(det) >= 2:
                src_ip_raw = det[0]
                dst_ip_raw = det[1]
                has_directional_ambiguity = True
            elif len(det) == 1:
                src_ip_raw = det[0]

        src_clean_ip, src_is_priv, _ = Normalizer.classify_ip(src_ip_raw)
        dst_clean_ip, dst_is_priv, _ = Normalizer.classify_ip(dst_ip_raw)

        if src_ip_raw and not src_clean_ip:
            warnings.append(f"Malformed source IP: {src_ip_raw}")
            error_codes.append("ERR_INVALID_SRC_IP")
        if dst_ip_raw and not dst_clean_ip:
            warnings.append(f"Malformed destination IP: {dst_ip_raw}")
            error_codes.append("ERR_INVALID_DST_IP")

        src_port = None
        if src_port_raw:
            try:
                p = int(src_port_raw)
                if 1 <= p <= 65535:
                    src_port = p
            except (ValueError, TypeError):
                warnings.append(f"Invalid src_port: {src_port_raw}")

        dst_port = None
        if dst_port_raw:
            try:
                p = int(dst_port_raw)
                if 1 <= p <= 65535:
                    dst_port = p
            except (ValueError, TypeError):
                warnings.append(f"Invalid dst_port: {dst_port_raw}")

        direction = Normalizer.determine_direction(src_clean_ip, dst_clean_ip, src_is_priv, dst_is_priv)

        protocol = fields.pop("network_transport", None) or fields.pop("proto", None) or fields.pop("protocol", None)
        if protocol:
            protocol = str(protocol).lower()

        # 3. Action and Severity
        action_raw = fields.pop("event.action", None) or fields.pop("action", None) or fields.pop("act", None)
        normalized_action_str = Normalizer.normalize_action(action_raw)
        action_enum = EventAction(normalized_action_str)

        severity_raw = fields.pop("severity", None) or fields.pop("syslog_severity", None)
        normalized_sev_str = Normalizer.normalize_severity(severity_raw)
        sev_enum = EventSeverity(normalized_sev_str)

        status_raw = fields.pop("status", None) or fields.pop("result", None)
        status_enum = EventStatus.UNKNOWN
        if status_raw:
            s_lower = str(status_raw).lower()
            if s_lower in ("success", "ok", "yes", "passed"):
                status_enum = EventStatus.SUCCESS
            elif s_lower in ("failure", "failed", "no", "error"):
                status_enum = EventStatus.FAILURE

        # 4. Infer Category
        category = EventCategory.UNKNOWN
        event_type = "generic"

        if src_clean_ip or dst_clean_ip or protocol:
            category = EventCategory.NETWORK
            event_type = "connection"
        if any(k in str(fields).lower() for k in ("login", "auth", "passwd", "password", "session")):
            category = EventCategory.AUTHENTICATION
            event_type = "login"
        if "comm" in fields or "pid" in fields or "exe" in fields or "process" in fields:
            category = EventCategory.SYSTEM
            event_type = "process_activity"
        if parse_res.format_name in ("AUDITD", "CEF", "LEEF"):
            category = EventCategory.SECURITY

        # 5. Actor & Process
        user_name = (
            fields.pop("actor.user_name", None) or
            fields.pop("user_name", None) or
            fields.pop("user", None) or
            fields.pop("usr", None) or
            fields.pop("duser", None) or
            fields.pop("suser", None)
        )
        proc_name = (
            fields.pop("process.name", None) or
            fields.pop("process_name", None) or
            fields.pop("app_name", None) or
            fields.pop("comm", None)
        )
        proc_pid = None
        pid_raw = fields.pop("pid", None) or fields.pop("procid", None)
        if pid_raw:
            try:
                proc_pid = int(pid_raw)
            except (ValueError, TypeError):
                pass

        # 6. Device Details
        device_host = fields.pop("hostname", None) or fields.pop("device_host", None)
        device_vendor = fields.pop("device_vendor", None) or fields.pop("vendor", None)
        device_product = fields.pop("device_product", None) or fields.pop("product", None)

        # 7. Threat Intelligence & MITRE ATT&CK Tactical Correlation
        mitre_id = None
        mitre_name = None
        tactic = None
        risk_score = 15

        raw_lower = raw_clean.lower()
        if any(x in raw_lower for x in ("ncat", "nc -e", "/bin/sh", "cmd.exe", "/bin/bash")):
            mitre_id = "T1059.004"
            mitre_name = "Unix Shell / Command Execution"
            tactic = "Execution"
            risk_score = 90
        elif action_enum == EventAction.DENY and dst_port in (22, 3389, 445):
            mitre_id = "T1110"
            mitre_name = "Brute Force / Lateral Probe"
            tactic = "Credential Access"
            risk_score = 75
        elif any(x in raw_lower for x in ("secretretrieved", "vault", "password", "shadow")):
            mitre_id = "T1555"
            mitre_name = "Credentials from Password Stores"
            tactic = "Credential Access"
            risk_score = 80
        elif direction == "outbound" and dst_port in (4444, 1337, 8080, 9092):
            mitre_id = "T1071.001"
            mitre_name = "Web Protocols / C2 Channel"
            tactic = "Command and Control"
            risk_score = 70
        elif direction == "internal" and dst_port in (445, 139):
            mitre_id = "T1021.002"
            mitre_name = "SMB / Windows Admin Shares"
            tactic = "Lateral Movement"
            risk_score = 65

        from core.schema import ThreatIntel
        threat_intel = ThreatIntel(
            mitre_technique_id=mitre_id,
            mitre_technique_name=mitre_name,
            tactic=tactic,
            risk_score=risk_score
        )

        # 8. Construct Record
        record = CanonicalLogRecord(
            raw_log=raw_clean,
            unmapped=fields,  # All remaining unmapped tokens preserved
            timestamp=ts_meta,
            src_endpoint=Endpoint(ip=src_clean_ip, port=src_port, is_private=src_is_priv),
            dst_endpoint=Endpoint(ip=dst_clean_ip, port=dst_port, is_private=dst_is_priv),
            network=NetworkDetails(protocol=protocol, direction=direction),
            device=DeviceDetails(hostname=device_host, vendor=device_vendor, product=device_product),
            actor=ActorDetails(user_name=str(user_name) if user_name else None),
            process=ProcessDetails(name=str(proc_name) if proc_name else None, pid=proc_pid),
            threat_intel=threat_intel
        )
        record.event.category = category
        record.event.type = event_type
        record.event.action = action_enum
        record.event.severity = sev_enum
        record.event.status = status_enum

        # 8. Multi-Level Confidence Scoring
        confidence_breakdown = ConfidenceScorer.compute_composite_confidence(
            format_detected=parse_res.format_name,
            parser_used=parser_name,
            is_exact_syntax=parse_res.is_exact_syntax,
            extracted_fields=parse_res.extracted_fields,
            mapped_record=record.model_dump(),
            has_directional_ambiguity=has_directional_ambiguity,
            warnings=warnings
        )

        latency_us = int((time.perf_counter_ns() - start_ns) / 1000)

        record.processing_metadata = ProcessingMetadata(
            format_detected=parse_res.format_name,
            parser_used=parser_name,
            inference_used=inference_used,
            latency_us=latency_us,
            confidence=confidence_breakdown,
            warnings=warnings,
            error_codes=error_codes
        )

        return record

    def process_batch(self, logs: List[str]) -> List[CanonicalLogRecord]:
        """
        Batch processing for high throughput.
        """
        return [self.process_log(l) for l in logs if l.strip()]

