"""
Central Configuration for Universal Log Pre-processing Framework (NTRO / SIH26156)
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True, parents=True)

# Database and Storage Paths
DUCKDB_PATH = str(DATA_DIR / "logs_analytics.duckdb")
RULES_DB_PATH = str(DATA_DIR / "learned_rules.sqlite")
REVIEW_QUEUE_DB_PATH = str(DATA_DIR / "review_queue.sqlite")
DEAD_LETTER_PATH = str(DATA_DIR / "dead_letter.jsonl")

# Confidence Thresholds
# >= AUTO_ACCEPT: Direct downstream ingestion without review
CONFIDENCE_AUTO_ACCEPT = 0.85
# >= REVIEW: Ingested with warning / flagged for background review
# < REVIEW: Routed to Human-In-The-Loop review queue & Dead-Letter log
CONFIDENCE_REVIEW_THRESHOLD = 0.60

# Inference Backend Configuration
# Options: "heuristic" (100% offline, statistical), "ollama" (local SLM), "gemini" (cloud API)
INFERENCE_BACKEND = os.getenv("INFERENCE_BACKEND", "heuristic").lower()
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

# Ingestion / Pipeline Performance
MAX_BUFFER_LINES = 10000
MULTILINE_MAX_BYTES = 65536
FLUSH_INTERVAL_SECONDS = 2.0
BENCHMARK_CORPUS_DIR = BASE_DIR / "benchmarks" / "test_corpus"
BENCHMARK_CORPUS_DIR.mkdir(exist_ok=True, parents=True)

