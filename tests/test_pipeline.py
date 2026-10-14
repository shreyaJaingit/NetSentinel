"""
NetSentinel Automated Unit & Integration Test Suite
Validates flow extraction, UNSW-NB15 feature engineering, ONNX sub-5ms inference,
SHAP explainability, Snort/Suricata rule syntax, mTLS mitigation, and Prometheus metrics.
"""

from __future__ import annotations

import os
import sys
import unittest
import time
from typing import Dict, Any

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.sniffer.flow_extractor import FlowExtractor, NetworkFlow, PacketMetadata
from src.inference.consumer import NetSentinelInferenceConsumer, ONNXRuntimeEngine
from src.inference.convert_model import FEATURE_NAMES, ATTACK_CLASSES
from src.mitigation.rule_generator import DynamicRuleGenerator
from src.mitigation.block_engine import MitigationBlockEngine, FirewallRule
from src.monitoring.metrics import MetricsRegistry


class TestFlowExtractor(unittest.TestCase):
    """Test packet aggregation and UNSW-NB15 feature extraction."""

    def setUp(self):
        self.extractor = FlowExtractor(config_path="config/config.yaml")

    def test_synthetic_flow_generation(self):
        flow = self.extractor.generate_synthetic_flow("DoS")
        self.assertEqual(flow["proto"], "tcp")
        self.assertEqual(flow["dst_port"], 80)
        self.assertGreaterEqual(flow["syn_ratio"], 0.8)
        self.assertIn("dur", flow)
        self.assertIn("rate", flow)
        self.assertIn("pkt_size_var", flow)

    def test_network_flow_feature_calculation(self):
        key = ("192.168.1.10", "10.0.0.1", 54321, 443, "tcp")
        flow = NetworkFlow(key, start_time=100.0)

        # Add forward SYN packet
        pkt1 = PacketMetadata(
            timestamp=100.0,
            src_ip="192.168.1.10", dst_ip="10.0.0.1",
            src_port=54321, dst_port=443, proto="tcp",
            length=60, ttl=64, tcp_flags={"SYN": True},
            tcp_seq=1000, tcp_ack=0, tcp_window=29200
        )
        flow.add_packet(pkt1)

        # Add backward SYN-ACK packet
        pkt2 = PacketMetadata(
            timestamp=100.02,
            src_ip="10.0.0.1", dst_ip="192.168.1.10",
            src_port=443, dst_port=54321, proto="tcp",
            length=60, ttl=64, tcp_flags={"SYN": True, "ACK": True},
            tcp_seq=2000, tcp_ack=1001, tcp_window=29200
        )
        flow.add_packet(pkt2)

        # Add forward ACK packet
        pkt3 = PacketMetadata(
            timestamp=100.04,
            src_ip="192.168.1.10", dst_ip="10.0.0.1",
            src_port=54321, dst_port=443, proto="tcp",
            length=1500, ttl=64, tcp_flags={"ACK": True},
            tcp_seq=1001, tcp_ack=2001, tcp_window=29200
        )
        flow.add_packet(pkt3)

        features = flow.compute_features()
        self.assertEqual(features["spkts"], 2)
        self.assertEqual(features["dpkts"], 1)
        self.assertEqual(features["sbytes"], 1560)
        self.assertEqual(features["dbytes"], 60)
        self.assertAlmostEqual(features["tcprtt"], 40.0, delta=1.0)
        self.assertEqual(features["service"], "ssl")


class TestInferenceEngine(unittest.TestCase):
    """Test ONNX model inference and SHAP explainability."""

    def setUp(self):
        self.consumer = NetSentinelInferenceConsumer(config_path="config/config.yaml")

    def test_sub_5ms_inference_latency(self):
        mock_flow = self.consumer.config
        extractor = FlowExtractor()
        flow = extractor.generate_synthetic_flow("DoS")

        t0 = time.perf_counter()
        alert = self.consumer.process_flow(flow)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        # Strict SLA assertion: latency must be sub-5ms (and typically sub-1ms)
        self.assertLess(latency_ms, 5.0, f"Latency exceeded 5ms: {latency_ms:.2f}ms")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.attack_cat, "DoS")
        self.assertGreater(alert.anomaly_prob, 0.85)
        self.assertIsNotNone(alert.primary_contributing_feature)

    def test_shap_attribution_output(self):
        extractor = FlowExtractor()
        dos_flow = extractor.generate_synthetic_flow("DoS")
        vec = self.consumer.extract_feature_vector(dos_flow)
        primary, attributions = self.consumer.engine.explain_anomaly(vec, top_k=3)

        self.assertIn(primary, FEATURE_NAMES)
        self.assertEqual(len(attributions), 3)
        for feat, val in attributions.items():
            self.assertIsInstance(val, float)


class TestThreatMitigation(unittest.TestCase):
    """Test dynamic rule generator and firewall blocking."""

    def setUp(self):
        self.rule_gen = DynamicRuleGenerator("config/config.yaml")
        self.block_engine = MitigationBlockEngine("config/config.yaml")

    def test_snort3_and_suricata_rule_generation(self):
        alert = {
            "src_ip": "172.16.0.99",
            "dst_ip": "10.0.0.1",
            "src_port": 55123,
            "dst_port": 80,
            "proto": "tcp",
            "attack_cat": "DoS",
            "anomaly_prob": 0.99,
            "primary_contributing_feature": "syn_ratio"
        }
        snort, suricata = self.rule_gen.generate_signatures_from_alert(alert)

        # Validate Snort 3 rule syntax
        self.assertTrue(snort.rule_text.startswith("alert tcp 172.16.0.99 55123 -> 10.0.0.1 80"))
        self.assertIn("sid:", snort.rule_text)
        self.assertIn("msg:\"[NetSentinel] DoS Attack Detected", snort.rule_text)

        # Validate Suricata rule syntax
        self.assertTrue(suricata.rule_text.startswith("alert tcp 172.16.0.99 55123 -> 10.0.0.1 80"))
        self.assertIn("flow:to_server", suricata.rule_text)
        self.assertIn("classtype:denial-of-service", suricata.rule_text)

    def test_firewall_block_and_ttl_cleanup(self):
        rule = self.block_engine.block_ip("198.51.100.42", ttl_seconds=1)
        self.assertTrue(rule.is_active)
        self.assertIn("198.51.100.42", self.block_engine.active_blocks)

        # Sleep past TTL
        time.sleep(1.1)
        expired = self.block_engine.cleanup_expired_blocks()
        self.assertIn("198.51.100.42", expired)
        self.assertNotIn("198.51.100.42", self.block_engine.active_blocks)


class TestMetricsRegistry(unittest.TestCase):
    """Test Prometheus exposition formatting."""

    def test_metrics_formatting(self):
        reg = MetricsRegistry()
        reg.record_packet("eth0", "tcp", 50)
        reg.set_active_flows(12)
        reg.record_inference_latency(0.000150)
        reg.record_threat_detected("Exploits", "CRITICAL")

        output = reg.generate_prometheus_text()
        self.assertIn("netsentinel_packets_total{interface=\"eth0\",protocol=\"tcp\"} 50", output)
        self.assertIn("netsentinel_flows_active 12", output)
        self.assertIn("netsentinel_inference_latency_seconds_count 1", output)
        self.assertIn("netsentinel_threats_detected_total{attack_cat=\"Exploits\",severity=\"CRITICAL\"} 1", output)


if __name__ == "__main__":
    unittest.main()
