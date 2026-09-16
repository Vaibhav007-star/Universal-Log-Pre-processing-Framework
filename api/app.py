"""
FastAPI REST Service for Universal Log Pre-processing Framework.
Exposes endpoints for log ingestion, deep explainability, HITL review, and analytics.
Also serves the AegisLog Command Portal landing page at http://localhost:8000/
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from pathlib import Path
import time

from core.pipeline import UniversalLogPipeline
from core.schema import CanonicalLogRecord
from core.multiline import MultilineAssembler
import config

app = FastAPI(
    title="Universal Log Pre-processing Framework (NTRO / SIH26156)",
    description="Defense-grade, deterministic-first universal log normalization engine compliant with OCSF v1.1",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# ── Serve the Command Portal landing page ──────────────────────────────────────
_STATIC_DIR = Path(__file__).parent / "static"
app.mount("/portal", StaticFiles(directory=str(_STATIC_DIR), html=True), name="portal")

# Global pipeline instance
pipeline = UniversalLogPipeline(
    enable_duckdb=True,
    enable_dead_letter=True,
    inference_backend=config.INFERENCE_BACKEND
)


class ParseRequest(BaseModel):
    raw_log: str = Field(..., description="Single raw log line or multiline block")


class BatchIngestRequest(BaseModel):
    logs: List[str] = Field(..., description="List of raw log lines")
    assemble_multiline: bool = Field(default=False, description="Whether to reassemble multiline exception traces")


class HITLCorrectionRequest(BaseModel):
    event_id: str
    signature_id: str
    template_str: str
    regex_pattern: str
    corrected_mappings: Dict[str, str]
    sample_log: str


@app.get("/", include_in_schema=False)
def root():
    """Redirect root to the AegisLog Command Portal landing page."""
    return RedirectResponse(url="/portal/index.html")


@app.get("/health")
def health_check():
    """System health check for Docker / load balancer probes."""
    return {
        "status": "healthy",
        "engine": "Universal Log Pre-processing Framework",
        "target_schema": "OCSF v1.1 / ECS",
        "inference_backend": config.INFERENCE_BACKEND,
        "active_parsers": len(pipeline.registry._parsers)
    }


@app.post("/api/v1/parse", response_model=CanonicalLogRecord)
def parse_single_log(req: ParseRequest):
    """
    Parses a single log line into the canonical OCSF v1.1 schema.
    """
    record = pipeline.process_log(req.raw_log)
    return record


@app.post("/api/v1/ingest")
def batch_ingest(req: BatchIngestRequest):
    """
    High-throughput batch ingestion of heterogeneous logs.
    """
    start_time = time.perf_counter()
    logs_to_process = req.logs

    if req.assemble_multiline:
        assembler = MultilineAssembler()
        logs_to_process = list(assembler.process_stream(req.logs))

    records = pipeline.process_batch(logs_to_process)
    duration = time.perf_counter() - start_time
    eps = len(records) / duration if duration > 0 else 0

    return {
        "ingested_count": len(records),
        "duration_seconds": round(duration, 4),
        "throughput_eps": round(eps, 1),
        "sample_normalized_id": records[0].event.id if records else None
    }


@app.get("/api/v1/explain")
def explain_log(log: str = Query(..., description="Raw log to inspect")):
    """
    Deep explainability and debug view showing every step of normalization.
    """
    record = pipeline.process_log(log)

    return {
        "raw_input": record.raw_log,
        "explainability": {
            "format_detected": record.processing_metadata.format_detected,
            "parser_selected": record.processing_metadata.parser_used,
            "inference_used": record.processing_metadata.inference_used,
            "latency_microseconds": record.processing_metadata.latency_us,
            "confidence": record.processing_metadata.confidence.model_dump(),
            "extracted_canonical_fields": {
                "timestamp": record.timestamp.model_dump(),
                "event": record.event.model_dump(),
                "src_endpoint": record.src_endpoint.model_dump(),
                "dst_endpoint": record.dst_endpoint.model_dump(),
                "network": record.network.model_dump(),
                "device": record.device.model_dump(),
                "actor": record.actor.model_dump(),
                "process": record.process.model_dump(),
            },
            "unmapped_retained_fields": record.unmapped,
            "warnings": record.processing_metadata.warnings,
            "error_codes": record.processing_metadata.error_codes
        }
    }


@app.get("/api/v1/rules")
def list_learned_rules():
    """
    Returns all dynamically synthesized parsers stored in SQLite.
    """
    return {
        "count": len(pipeline.rule_store.list_rules()),
        "rules": pipeline.rule_store.list_rules()
    }


@app.get("/api/v1/hitl/pending")
def get_pending_reviews(limit: int = 50):
    """
    Retrieves low-confidence events awaiting cybersecurity analyst triage.
    """
    pending = pipeline.review_queue.get_pending(limit=limit)
    return {
        "pending_count": len(pending),
        "items": pending
    }


@app.post("/api/v1/hitl/approve")
def approve_and_learn_rule(req: HITLCorrectionRequest):
    """
    Commits analyst corrections into permanent SQLite store and activates rule in runtime memory.
    """
    success = pipeline.feedback_handler.apply_analyst_correction(
        event_id=req.event_id,
        signature_id=req.signature_id,
        template_str=req.template_str,
        regex_pattern=req.regex_pattern,
        corrected_mappings=req.corrected_mappings,
        sample_log=req.sample_log
    )
    return {"status": "success" if success else "failed", "signature_id": req.signature_id}


@app.get("/api/v1/stats")
def get_system_stats():
    """
    Returns aggregate storage and analytics metrics from DuckDB.
    """
    if pipeline.duckdb_sink:
        metrics = pipeline.duckdb_sink.get_aggregate_metrics()
    else:
        metrics = {"error": "DuckDB sink disabled"}

    metrics["active_registered_parsers"] = [p["name"] for p in pipeline.registry.list_parsers()]
    return metrics

