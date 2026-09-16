"""
Performance & Accuracy Benchmarking Suite.
Measures Throughput (EPS), Latency Percentiles (p50/p90/p99), and Normalization Accuracy.
"""

import time
import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.pipeline import UniversalLogPipeline
from benchmarks.generate_synthetic_data import generate_log_corpus
import config


def run_benchmark(count: int = 5000, output_json: str = "benchmark_results.json") -> Dict[str, Any]:
    print(f"\n================================================================================")
    print(f" UNIVERSAL LOG PRE-PROCESSING FRAMEWORK - BENCHMARK SUITE (NTRO / SIH26156)")
    print(f"================================================================================")
    print(f"[*] Generating {count} heterogeneous logs across 8 distinct formats...")
    logs = generate_log_corpus(count)

    # Initialize pipeline with in-memory SQLite / disabled disk write for maximum raw throughput measurement
    pipeline = UniversalLogPipeline(
        enable_duckdb=False,
        enable_dead_letter=False,
        inference_backend="heuristic"
    )

    print(f"[*] Commencing pipeline execution on {count} log stream...")
    latencies_us: List[int] = []
    format_counts: Dict[str, int] = {}
    high_conf_count = 0
    total_parsed_successfully = 0
    core_fields_mapped_count = 0

    start_benchmark = time.perf_counter()

    for raw in logs:
        rec = pipeline.process_log(raw)
        lat = rec.processing_metadata.latency_us
        latencies_us.append(lat)

        fmt = rec.processing_metadata.format_detected
        format_counts[fmt] = format_counts.get(fmt, 0) + 1

        conf = rec.processing_metadata.confidence.overall_confidence
        if conf >= config.CONFIDENCE_AUTO_ACCEPT:
            high_conf_count += 1

        if rec.processing_metadata.parser_used != "NONE":
            total_parsed_successfully += 1

        # Check if core fields were populated (timestamp + at least one endpoint or actor)
        if rec.timestamp.normalized and (rec.src_endpoint.ip or rec.dst_endpoint.ip or rec.actor.user_name):
            core_fields_mapped_count += 1

    total_duration_sec = time.perf_counter() - start_benchmark
    throughput_eps = count / total_duration_sec if total_duration_sec > 0 else 0

    latencies_us.sort()
    min_lat = latencies_us[0] if latencies_us else 0
    p50_lat = latencies_us[int(len(latencies_us) * 0.50)] if latencies_us else 0
    p90_lat = latencies_us[int(len(latencies_us) * 0.90)] if latencies_us else 0
    p99_lat = latencies_us[int(len(latencies_us) * 0.99)] if latencies_us else 0
    max_lat = latencies_us[-1] if latencies_us else 0
    avg_lat = sum(latencies_us) / len(latencies_us) if latencies_us else 0

    parsing_accuracy = (total_parsed_successfully / count) * 100
    schema_accuracy = (core_fields_mapped_count / count) * 100

    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_records_evaluated": count,
        "total_duration_seconds": round(total_duration_sec, 4),
        "throughput_eps": round(throughput_eps, 1),
        "latency_percentiles_us": {
            "min": min_lat,
            "p50_median": p50_lat,
            "p90": p90_lat,
            "p99": p99_lat,
            "max": max_lat,
            "avg": round(avg_lat, 1)
        },
        "accuracy_metrics": {
            "parsing_success_rate_pct": round(parsing_accuracy, 2),
            "schema_mapping_accuracy_pct": round(schema_accuracy, 2),
            "high_confidence_rate_pct": round((high_conf_count / count) * 100, 2)
        },
        "format_distribution": format_counts
    }

    # Print ASCII Table
    print(f"\n[+] BENCHMARK EXECUTION COMPLETED")
    print(f"--------------------------------------------------------------------------------")
    print(f" Total Ingested Logs      : {count:,} events")
    print(f" Total Elapsed Time       : {total_duration_sec:.3f} seconds")
    print(f" Pipeline Throughput      : {throughput_eps:,.1f} Events / Second (EPS)")
    print(f" Median Latency (p50)     : {p50_lat} microseconds ({p50_lat/1000:.3f} ms)")
    print(f" 99th Percentile (p99)    : {p99_lat} microseconds ({p99_lat/1000:.3f} ms)")
    print(f" Parsing Success Rate     : {parsing_accuracy:.2f}% (Zero Silent Drops)")
    print(f" Schema-Mapping Accuracy  : {schema_accuracy:.2f}%")
    print(f" Auto-Accept Confidence   : {(high_conf_count / count) * 100:.2f}%")
    print(f"--------------------------------------------------------------------------------")
    print(f" Format Breakdown:")
    for fmt, c in sorted(format_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (c / count) * 100
        print(f"   - {fmt:<22}: {c:>5} logs ({pct:>5.1f}%)")
    print(f"================================================================================\n")

    # Save to disk
    out_path = Path(output_json)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Saved benchmark artifact to {out_path.resolve()}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run log pipeline benchmarks")
    parser.add_argument("--count", type=int, default=3000, help="Number of synthetic logs to evaluate")
    parser.add_argument("--out", type=str, default="benchmark_results.json", help="Output JSON path")
    args = parser.parse_args()

    run_benchmark(count=args.count, output_json=args.out)
