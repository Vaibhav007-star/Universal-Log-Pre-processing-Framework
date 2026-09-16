"""
Columnar Storage and Analytics Engine via Embedded DuckDB.
Provides sub-second analytical queries and micro-batch writes without cluster overhead.
"""

import duckdb
import json
from typing import List, Dict, Any, Optional
from core.schema import CanonicalLogRecord
import config


class DuckDBSink:
    """
    Embedded analytical sink for canonical OCSF log records.
    """

    def __init__(self, db_path: str = config.DUCKDB_PATH):
        self.db_path = db_path
        self._init_tables()

    def _get_conn(self) -> duckdb.DuckDBPyConnection:
        return duckdb.connect(self.db_path)

    def _init_tables(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS normalized_logs (
                id VARCHAR PRIMARY KEY,
                created_time VARCHAR,
                category VARCHAR,
                event_type VARCHAR,
                action VARCHAR,
                severity VARCHAR,
                status VARCHAR,
                timestamp_raw VARCHAR,
                timestamp_normalized VARCHAR,
                timestamp_epoch_us BIGINT,
                src_ip VARCHAR,
                src_port INTEGER,
                src_is_private BOOLEAN,
                dst_ip VARCHAR,
                dst_port INTEGER,
                dst_is_private BOOLEAN,
                network_protocol VARCHAR,
                network_direction VARCHAR,
                device_hostname VARCHAR,
                device_vendor VARCHAR,
                actor_user_name VARCHAR,
                process_name VARCHAR,
                process_pid INTEGER,
                format_detected VARCHAR,
                parser_used VARCHAR,
                inference_used BOOLEAN,
                latency_us INTEGER,
                confidence_overall DOUBLE,
                confidence_format DOUBLE,
                confidence_field DOUBLE,
                confidence_schema DOUBLE,
                raw_log VARCHAR,
                unmapped_json VARCHAR,
                error_codes_json VARCHAR,
                mitre_id VARCHAR,
                risk_score INTEGER
            )
        """)
        # Safe column migration if table already existed
        try:
            conn.execute("ALTER TABLE normalized_logs ADD COLUMN IF NOT EXISTS mitre_id VARCHAR")
            conn.execute("ALTER TABLE normalized_logs ADD COLUMN IF NOT EXISTS risk_score INTEGER")
        except Exception:
            pass
        conn.close()

    def insert_record(self, record: CanonicalLogRecord):
        """
        Inserts a single CanonicalLogRecord.
        """
        self.insert_batch([record])

    def insert_batch(self, records: List[CanonicalLogRecord]):
        """
        High-speed batch insertion into DuckDB.
        """
        if not records:
            return

        rows = []
        for r in records:
            rows.append((
                r.event.id,
                r.event.created_time,
                r.event.category.value,
                r.event.type,
                r.event.action.value,
                r.event.severity.value,
                r.event.status.value,
                r.timestamp.raw,
                r.timestamp.normalized,
                r.timestamp.epoch_us,
                r.src_endpoint.ip,
                r.src_endpoint.port,
                r.src_endpoint.is_private,
                r.dst_endpoint.ip,
                r.dst_endpoint.port,
                r.dst_endpoint.is_private,
                r.network.protocol,
                r.network.direction,
                r.device.hostname,
                r.device.vendor,
                r.actor.user_name,
                r.process.name,
                r.process.pid,
                r.processing_metadata.format_detected,
                r.processing_metadata.parser_used,
                r.processing_metadata.inference_used,
                r.processing_metadata.latency_us,
                r.processing_metadata.confidence.overall_confidence,
                r.processing_metadata.confidence.format_confidence,
                r.processing_metadata.confidence.field_extraction_confidence,
                r.processing_metadata.confidence.schema_mapping_confidence,
                r.raw_log,
                json.dumps(r.unmapped),
                json.dumps(r.processing_metadata.error_codes),
                r.threat_intel.mitre_technique_id,
                r.threat_intel.risk_score
            ))

        conn = self._get_conn()
        conn.executemany("""
            INSERT OR REPLACE INTO normalized_logs VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?
            )
        """, rows)
        conn.close()

    def query(self, sql: str) -> List[Dict[str, Any]]:
        """
        Executes arbitrary SQL query and returns list of dictionaries.
        """
        conn = self._get_conn()
        rel = conn.execute(sql)
        cols = [desc[0] for desc in rel.description]
        results = [dict(zip(cols, row)) for row in rel.fetchall()]
        conn.close()
        return results

    def get_aggregate_metrics(self) -> Dict[str, Any]:
        """
        Computes real-time dashboard analytics.
        """
        conn = self._get_conn()
        stats = conn.execute("""
            SELECT 
                COUNT(*) as total_logs,
                AVG(confidence_overall) as avg_confidence,
                AVG(latency_us) as avg_latency_us,
                SUM(CASE WHEN inference_used THEN 1 ELSE 0 END) as inference_count,
                SUM(CASE WHEN confidence_overall >= 0.85 THEN 1 ELSE 0 END) as high_conf_count,
                SUM(CASE WHEN confidence_overall < 0.60 THEN 1 ELSE 0 END) as low_conf_count
            FROM normalized_logs
        """).fetchone()

        formats = conn.execute("""
            SELECT format_detected, count(*) as cnt 
            FROM normalized_logs 
            GROUP BY 1 ORDER BY 2 DESC
        """).fetchall()

        actions = conn.execute("""
            SELECT action, count(*) as cnt 
            FROM normalized_logs 
            GROUP BY 1 ORDER BY 2 DESC
        """).fetchall()

        conn.close()

        return {
            "total_logs": stats[0] if stats else 0,
            "avg_confidence": round(stats[1], 3) if stats and stats[1] is not None else 0.0,
            "avg_latency_us": round(stats[2], 1) if stats and stats[2] is not None else 0.0,
            "inference_count": stats[3] if stats else 0,
            "high_conf_count": stats[4] if stats else 0,
            "low_conf_count": stats[5] if stats else 0,
            "formats_distribution": dict(formats),
            "actions_distribution": dict(actions)
        }

