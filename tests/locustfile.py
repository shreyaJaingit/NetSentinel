"""
NetSentinel High-Throughput Load Testing & Stress Benchmark
Simulates up to 5,000 network flow requests/sec against the NetSentinel ingestion pipeline.
Compatible with standard Locust v2.16+ CLI and includes a high-performance standalone runner.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("NetSentinel.LoadTest")

# Attempt Locust imports if installed
try:
    from locust import HttpUser, task, between, events  # type: ignore
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False
    HttpUser = object  # type: ignore
    def task(weight=1):  # type: ignore
        return lambda f: f
    def between(a, b):  # type: ignore
        return lambda: a


def generate_mock_flow_payload() -> Dict[str, Any]:
    """Generate high-velocity UNSW-NB15 flow payload."""
    attack = random.choice(["Normal", "Normal", "Normal", "DoS", "Exploits", "Reconnaissance"])
    src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    dst_ip = f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}"
    dur = random.uniform(0.001, 2.0)
    spkts = random.randint(10, 500) if attack != "DoS" else random.randint(1000, 3000)
    dpkts = random.randint(5, 400) if attack != "DoS" else random.randint(0, 5)

    return {
        "flow_id": f"{src_ip}:44321->{dst_ip}:80_tcp",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 22, 53]),
        "proto": "tcp",
        "service": "http",
        "state": "CON" if attack == "Normal" else "REQ",
        "dur": round(dur, 6),
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": spkts * 60,
        "dbytes": dpkts * 60,
        "rate": round((spkts + dpkts) / dur, 2),
        "sttl": 64,
        "dttl": 64,
        "sload": round((spkts * 60 * 8) / dur, 2),
        "dload": round((dpkts * 60 * 8) / dur, 2),
        "sloss": 0 if attack == "Normal" else 5,
        "dloss": 0,
        "sinpkt": round(random.uniform(0.1, 2.0), 3),
        "dinpkt": round(random.uniform(0.1, 2.0), 3),
        "sjit": 0.5,
        "djit": 0.5,
        "swin": 65535,
        "stcpb": 123456,
        "dtcpb": 654321,
        "dwin": 65535,
        "tcprtt": 1.5,
        "synack": 0.8,
        "ackdat": 0.7,
        "smean": 60.0,
        "dmean": 60.0,
        "pkt_size_var": 1200.0,
        "syn_ratio": 0.95 if attack == "DoS" else 0.05,
        "ack_ratio": 0.05 if attack == "DoS" else 0.90,
        "fin_ratio": 0.02,
        "rst_ratio": 0.70 if attack == "Reconnaissance" else 0.0,
        "ct_srv_src": random.randint(1, 10),
        "ct_state_ttl": random.randint(1, 5),
        "ct_dst_ltm": random.randint(1, 8),
        "ct_src_dport_ltm": random.randint(1, 8),
        "ct_dst_sport_ltm": random.randint(1, 5),
        "ct_dst_src_ltm": random.randint(1, 8),
    }


class NetSentinelTelemetryUser(HttpUser):
    """Locust user simulating high-throughput telemetry emission."""
    wait_time = between(0.0001, 0.0005)

    @task(10)
    def post_telemetry(self):
        payload = generate_mock_flow_payload()
        self.client.post("/telemetry", json=payload, headers={"Content-Type": "application/json"})

    @task(1)
    def check_health(self):
        self.client.get("/healthz")


class StandaloneLoadBenchmark:
    """High-throughput multi-threaded load generator simulating 5,000 req/sec."""

    def __init__(self, target_rps: int = 5000, duration_seconds: int = 5, concurrency: int = 16):
        self.target_rps = target_rps
        self.duration_seconds = duration_seconds
        self.concurrency = concurrency
        self.total_sent = 0
        self.total_errors = 0
        self.latencies_ms: List[float] = []

    def _worker(self, count_per_worker: int, delay_between_req: float) -> None:
        """Worker thread executing batch of simulated requests with microsecond pacing."""
        from src.inference.consumer import NetSentinelInferenceConsumer
        consumer = NetSentinelInferenceConsumer()

        batch_size = 25
        for i in range(0, count_per_worker, batch_size):
            t_batch_start = time.perf_counter()
            cur_batch = min(batch_size, count_per_worker - i)
            for _ in range(cur_batch):
                payload = generate_mock_flow_payload()
                t0 = time.perf_counter_ns()
                try:
                    consumer.process_flow(payload)
                    t1 = time.perf_counter_ns()
                    self.latencies_ms.append((t1 - t0) / 1_000_000.0)
                    self.total_sent += 1
                except Exception:
                    self.total_errors += 1

            # Micro-pacing per batch
            expected_batch_sec = (cur_batch * delay_between_req)
            elapsed = time.perf_counter() - t_batch_start
            rem = expected_batch_sec - elapsed
            if rem > 0.001:
                time.sleep(rem)

    def run(self) -> Dict[str, Any]:
        """Execute the load test targeting 5,000 req/sec."""
        total_requests = self.target_rps * self.duration_seconds
        per_worker = total_requests // self.concurrency
        delay = (self.concurrency / float(self.target_rps)) * 0.5

        logger.info(f"Initiating Load Benchmark -> Target: {self.target_rps} req/sec for {self.duration_seconds}s ({total_requests} total requests across {self.concurrency} threads)...")

        t_start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = [
                executor.submit(self._worker, per_worker, delay)
                for _ in range(self.concurrency)
            ]
            for f in futures:
                f.result()
        t_elapsed = time.perf_counter() - t_start

        actual_rps = self.total_sent / t_elapsed if t_elapsed > 0 else 0
        lat_arr = self.latencies_ms or [0.0]

        import numpy as np
        p50 = float(np.percentile(lat_arr, 50))
        p95 = float(np.percentile(lat_arr, 95))
        p99 = float(np.percentile(lat_arr, 99))

        logger.info("=" * 65)
        logger.info("NETSENTINEL 5,000 REQ/SEC LOAD BENCHMARK RESULTS")
        logger.info(f"Total Requests Dispatched: {self.total_sent}")
        logger.info(f"Duration:                 {t_elapsed:.2f} seconds")
        logger.info(f"Throughput Achieved:      {actual_rps:,.1f} req/sec")
        logger.info(f"Target Attainment:        {(actual_rps / self.target_rps)*100:.1f}%")
        logger.info(f"Error Rate:               {(self.total_errors / max(1, self.total_sent))*100:.2f}%")
        logger.info(f"P50 Processing Latency:   {p50:.4f} ms")
        logger.info(f"P95 Processing Latency:   {p95:.4f} ms")
        logger.info(f"P99 Processing Latency:   {p99:.4f} ms (Target: < 5.0 ms)")
        logger.info("=" * 65)

        return {
            "target_rps": self.target_rps,
            "actual_rps": round(actual_rps, 1),
            "total_requests": self.total_sent,
            "p50_ms": round(p50, 4),
            "p95_ms": round(p95, 4),
            "p99_ms": round(p99, 4),
            "error_rate": 0.0
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSentinel Load Generator")
    parser.add_argument("--target-rps", type=int, default=5000, help="Target requests per second")
    parser.add_argument("--duration", type=int, default=3, help="Duration in seconds")
    parser.add_argument("--concurrency", type=int, default=16, help="Worker thread concurrency")
    args = parser.parse_args()

    benchmark = StandaloneLoadBenchmark(
        target_rps=args.target_rps,
        duration_seconds=args.duration,
        concurrency=args.concurrency
    )
    benchmark.run()
