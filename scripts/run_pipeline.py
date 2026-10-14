"""
NetSentinel Unified Pipeline Orchestrator & Demonstrator
Orchestrates end-to-end packet flow: Sniffer / Simulation -> Kafka Telemetry ->
Sub-5ms Inference -> SHAP Explainability -> Snort 3 / Suricata Rules ->
mTLS / Firewall Mitigation -> Prometheus / Grafana Observability.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Dict, Any

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.inference.consumer import NetSentinelInferenceConsumer, ThreatAlert
from src.mitigation.block_engine import MitigationBlockEngine
from src.monitoring.metrics import NetSentinelMetricsExporter, get_metrics_registry
from src.sniffer.flow_extractor import FlowExtractor
from src.utils.config import load_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("NetSentinel.Orchestrator")


def run_pipeline(mode: str = "simulation", count: int = 100, delay_ms: int = 5) -> None:
    logger.info("=" * 70)
    logger.info("BOOTSTRAPPING NETSENTINEL ENTERPRISE THREAT INTELLIGENCE PLATFORM")
    logger.info("=" * 70)

    config = load_config("config/config.yaml")
    metrics_reg = get_metrics_registry()

    # 1. Start Prometheus Exporter on :8000
    m_cfg = config.get("monitoring", {})
    exporter = NetSentinelMetricsExporter(
        host=m_cfg.get("host", "0.0.0.0"),
        port=int(m_cfg.get("port", 8000))
    )
    exporter.start()

    # 2. Initialize Mitigation Engine
    mitigation_engine = MitigationBlockEngine("config/config.yaml")

    # 3. Initialize Inference Consumer wired to Mitigation Engine
    def on_alert_detected(alert: ThreatAlert) -> None:
        metrics_reg.record_threat_detected(alert.attack_cat, alert.severity)
        logger.warning(
            f"ALERT [{alert.severity}]: {alert.attack_cat} detected on {alert.src_ip} "
            f"(P={alert.anomaly_prob:.2f}) | Root-Cause: {alert.primary_contributing_feature} "
            f"(SHAP: {alert.shap_attributions.get(alert.primary_contributing_feature, 0.0):+.3f})"
        )
        mit_event = mitigation_engine.handle_threat_alert(alert.to_dict())
        metrics_reg.record_mitigation_enacted("firewall_block", "ip")

    consumer = NetSentinelInferenceConsumer(
        config_path="config/config.yaml",
        alert_callback=on_alert_detected
    )

    # 4. Initialize Flow Extractor
    def on_flow_extracted(flow: Dict[str, Any]) -> None:
        metrics_reg.record_packet(iface="eth0", proto=flow.get("proto", "tcp"), count=flow.get("spkts", 1))
        metrics_reg.record_kafka_produced("network-telemetry", "success")

        # In-process consumer dispatch for simulation
        t0 = time.perf_counter()
        consumer.process_flow(flow)
        lat_sec = time.perf_counter() - t0
        metrics_reg.record_inference_latency(lat_sec)

    extractor = FlowExtractor(
        config_path="config/config.yaml",
        telemetry_callback=on_flow_extracted
    )

    # 5. Execute Simulation / Live Capture
    logger.info(f"Pipeline running in mode: {mode.upper()}...")
    try:
        if mode == "simulation":
            extractor.run_simulation(count=count, delay_ms=delay_ms)
        else:
            extractor.run_live()
    except KeyboardInterrupt:
        logger.info("Pipeline execution interrupted by user.")

    # 6. Summary Telemetry Report
    stats = consumer.get_latency_stats()
    logger.info("=" * 70)
    logger.info("NETSENTINEL REAL-TIME PIPELINE TELEMETRY SUMMARY")
    logger.info(f"Total Flows Ingested:      {consumer.total_processed}")
    logger.info(f"Security Threats Flagged:  {consumer.total_anomalies}")
    logger.info(f"Active Firewall Blocks:    {len(mitigation_engine.active_blocks)}")
    logger.info(f"P50 Inference Latency:     {stats['p50']:.4f} ms")
    logger.info(f"P95 Inference Latency:     {stats['p95']:.4f} ms")
    logger.info(f"P99 Inference Latency:     {stats['p99']:.4f} ms (SLA: < 5.0 ms)")
    logger.info(f"Prometheus Metrics URL:    http://localhost:8000/metrics")
    logger.info("=" * 70)

    # Keep metrics server alive briefly for verification
    time.sleep(1.0)
    exporter.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSentinel Pipeline Runner")
    parser.add_argument("--mode", choices=["simulation", "live"], default="simulation", help="Execution mode")
    parser.add_argument("--count", type=int, default=100, help="Simulated flow count")
    parser.add_argument("--delay-ms", type=int, default=5, help="Delay between flows in ms")
    args = parser.parse_args()

    run_pipeline(mode=args.mode, count=args.count, delay_ms=args.delay_ms)
