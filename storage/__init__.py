"""
Storage, analytics, and persistence sinks.
"""
from storage.duckdb_sink import DuckDBSink
from storage.dead_letter import DeadLetterSink

__all__ = ["DuckDBSink", "DeadLetterSink"]

