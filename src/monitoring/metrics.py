"""
NetSentinel Prometheus Metrics Exporter
Exposes real-time telemetry metrics on `/metrics` (port 8000) conforming to Prometheus 2.0 specs.
Tracks packet ingestion rate, active flows, Kafka streaming, inference latency histograms,
and automated threat mitigation actions.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

from ..utils.config import load_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("NetSentinel.Metrics")

# Standard Prometheus histogram buckets for sub-5ms low latency profiling
LATENCY_BUCKETS = [0.0001, 0.00025, 0.0005, 0.001, 0.002, 0.005, 0.010, 0.025, 0.050, 0.1, float("inf")]


class MetricsRegistry:
    """Thread-safe Prometheus metrics collector and formatter."""

    def __init__(self):
        self._lock = threading.Lock()

        # Counters and Gauges
        self.packets_total: Dict[tuple[str, str], int] = defaultdict(int)
        self.flows_active: int = 0
        self.kafka_produced_total: Dict[tuple[str, str], int] = defaultdict(int)

        # Latency Histogram
        self.latency_buckets_count: List[int] = [0] * len(LATENCY_BUCKETS)
        self.latency_sum: float = 0.0
        self.latency_count: int = 0

        # Threat and Mitigation Counters
        self.threats_detected_total: Dict[tuple[str, str], int] = defaultdict(int)
        self.mitigations_enacted_total: Dict[tuple[str, str], int] = defaultdict(int)

    def record_packet(self, iface: str = "eth0", proto: str = "tcp", count: int = 1) -> None:
        with self._lock:
            self.packets_total[(iface, proto)] += count

    def set_active_flows(self, count: int) -> None:
        with self._lock:
            self.flows_active = count

    def record_kafka_produced(self, topic: str = "network-telemetry", status: str = "success") -> None:
        with self._lock:
            self.kafka_produced_total[(topic, status)] += 1

    def record_inference_latency(self, latency_seconds: float) -> None:
        with self._lock:
            self.latency_sum += latency_seconds
            self.latency_count += 1
            for idx, bound in enumerate(LATENCY_BUCKETS):
                if latency_seconds <= bound:
                    self.latency_buckets_count[idx] += 1

    def record_threat_detected(self, attack_cat: str, severity: str = "HIGH") -> None:
        with self._lock:
            self.threats_detected_total[(attack_cat, severity)] += 1

    def record_mitigation_enacted(self, action: str = "firewall_block", target: str = "ip") -> None:
        with self._lock:
            self.mitigations_enacted_total[(action, target)] += 1

    def generate_prometheus_text(self) -> str:
        """Format all recorded metrics to Prometheus exposition format (text/plain; version=0.0.4)."""
        lines: List[str] = [
            "# HELP netsentinel_packets_total Total number of network packets ingested by sniffer",
            "# TYPE netsentinel_packets_total counter"
        ]

        with self._lock:
            # Packets
            if not self.packets_total:
                lines.append('netsentinel_packets_total{interface="eth0",protocol="tcp"} 0')
            for (iface, proto), val in self.packets_total.items():
                lines.append(f'netsentinel_packets_total{{interface="{iface}",protocol="{proto}"}} {val}')

            # Active flows
            lines.extend([
                "# HELP netsentinel_flows_active Current concurrent active network flows",
                "# TYPE netsentinel_flows_active gauge",
                f"netsentinel_flows_active {self.flows_active}"
            ])

            # Kafka produced
            lines.extend([
                "# HELP netsentinel_kafka_produced_total Total telemetry records published to Kafka topics",
                "# TYPE netsentinel_kafka_produced_total counter"
            ])
            if not self.kafka_produced_total:
                lines.append('netsentinel_kafka_produced_total{topic="network-telemetry",status="success"} 0')
            for (topic, status), val in self.kafka_produced_total.items():
                lines.append(f'netsentinel_kafka_produced_total{{topic="{topic}",status="{status}"}} {val}')

            # Inference Latency Histogram
            lines.extend([
                "# HELP netsentinel_inference_latency_seconds ONNX model inference latency in seconds",
                "# TYPE netsentinel_inference_latency_seconds histogram"
            ])
            cumulative = 0
            for idx, bound in enumerate(LATENCY_BUCKETS):
                cumulative += self.latency_buckets_count[idx]
                bound_str = "+Inf" if bound == float("inf") else f"{bound:.6f}"
                lines.append(f'netsentinel_inference_latency_seconds_bucket{{le="{bound_str}"}} {cumulative}')
            lines.append(f"netsentinel_inference_latency_seconds_sum {self.latency_sum:.6f}")
            lines.append(f"netsentinel_inference_latency_seconds_count {self.latency_count}")

            # Threats Detected
            lines.extend([
                "# HELP netsentinel_threats_detected_total Total security anomalies detected by UNSW-NB15 classifier",
                "# TYPE netsentinel_threats_detected_total counter"
            ])
            if not self.threats_detected_total:
                lines.append('netsentinel_threats_detected_total{attack_cat="Normal",severity="INFO"} 0')
            for (cat, sev), val in self.threats_detected_total.items():
                lines.append(f'netsentinel_threats_detected_total{{attack_cat="{cat}",severity="{sev}"}} {val}')

            # Mitigations Enacted
            lines.extend([
                "# HELP netsentinel_mitigations_enacted_total Total automated threat mitigations enforced",
                "# TYPE netsentinel_mitigations_enacted_total counter"
            ])
            if not self.mitigations_enacted_total:
                lines.append('netsentinel_mitigations_enacted_total{action="firewall_block",target="ip"} 0')
            for (action, target), val in self.mitigations_enacted_total.items():
                lines.append(f'netsentinel_mitigations_enacted_total{{action="{action}",target="{target}"}} {val}')

        return "\n".join(lines) + "\n"


_GLOBAL_REGISTRY = MetricsRegistry()


def get_metrics_registry() -> MetricsRegistry:
    return _GLOBAL_REGISTRY


class PrometheusRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler serving /metrics endpoint."""

    def do_GET(self) -> None:
        if self.path in ("/metrics", "/metrics/"):
            data = _GLOBAL_REGISTRY.generate_prometheus_text().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path in ("/", "/healthz"):
            resp = b'{"status": "healthy", "service": "netsentinel-metrics"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard HTTP access logs
        return


class NetSentinelMetricsExporter:
    """Manages the background HTTP server exposing Prometheus metrics."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8000):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start HTTP server in background daemon thread."""
        try:
            self.server = HTTPServer((self.host, self.port), PrometheusRequestHandler)
            self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self._thread.start()
            logger.info(f"Prometheus Metrics Exporter listening on http://{self.host}:{self.port}/metrics")
        except Exception as e:
            logger.error(f"Failed to bind Prometheus server on {self.host}:{self.port}: {e}")

    def stop(self) -> None:
        """Stop HTTP server cleanly."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("Prometheus Metrics Exporter stopped.")


if __name__ == "__main__":
    import time
    cfg = load_config()
    m_cfg = cfg.get("monitoring", {})
    exporter = NetSentinelMetricsExporter(
        host=m_cfg.get("host", "0.0.0.0"),
        port=int(m_cfg.get("port", 8000))
    )
    exporter.start()

    # Pre-populate sample metrics for immediate visualization
    reg = get_metrics_registry()
    reg.record_packet("eth0", "tcp", 2500)
    reg.record_packet("eth0", "udp", 650)
    reg.set_active_flows(18)
    reg.record_kafka_produced("network-telemetry", "success")
    reg.record_inference_latency(0.000085)  # 0.085 ms
    reg.record_inference_latency(0.000120)  # 0.120 ms
    reg.record_threat_detected("DoS", "CRITICAL")
    reg.record_mitigation_enacted("firewall_block", "ip")

    logger.info("Metrics exporter running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        exporter.stop()
