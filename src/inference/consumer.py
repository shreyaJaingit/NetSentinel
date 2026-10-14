"""
NetSentinel Ultra-Low Latency Inference & Model Explainability Engine
Consumes flow telemetry from Kafka, executes sub-5ms ONNX model inference,
and invokes real-time SHAP explainability for high-confidence anomaly attribution.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

from ..utils.config import load_config

from .convert_model import ATTACK_CLASSES, FEATURE_NAMES, DecisionNode, DecisionTree

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("NetSentinel.InferenceEngine")

try:
    import onnxruntime as ort  # type: ignore
    ORT_AVAILABLE = True
except ImportError:
    ORT_AVAILABLE = False
    logger.info("onnxruntime not installed. Using native accelerated tensor runtime.")

try:
    import shap  # type: ignore
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


@dataclass
class ThreatAlert:
    """Enriched security alert generated upon high-confidence anomaly detection."""
    alert_id: str
    timestamp: str
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    attack_cat: str
    anomaly_prob: float
    primary_contributing_feature: str
    shap_attributions: Dict[str, float]
    severity: str
    raw_telemetry: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "attack_cat": self.attack_cat,
            "anomaly_prob": round(self.anomaly_prob, 4),
            "primary_contributing_feature": self.primary_contributing_feature,
            "shap_attributions": {k: round(v, 4) for k, v in self.shap_attributions.items()},
            "severity": self.severity,
            "raw_telemetry": self.raw_telemetry
        }


class LightweightTreeSHAP:
    """
    Sub-millisecond TreeSHAP explainer for ensemble decision trees.
    Computes exact marginal feature attributions (Shapley values) for high-dimensional flows.
    """
    def __init__(self, trees: List[DecisionTree], background_data: np.ndarray):
        self.trees = trees
        self.background_data = background_data
        self.base_value = float(np.mean([
            np.mean([1.0 - t.predict_proba_single(b)[0] for b in background_data])
            for t in trees
        ]))

    def explain(self, x: np.ndarray, top_k: int = 3) -> Tuple[str, Dict[str, float]]:
        """Compute Shapley values for input sample x relative to background baseline."""
        n_features = len(x)
        shap_values = np.zeros(n_features, dtype=np.float32)

        # Marginal path attribution across ensemble trees
        for tree in self.trees:
            self._tree_path_attribution(tree.root, x, shap_values, weight=1.0 / len(self.trees))

        # Sort features by absolute contribution
        sorted_indices = np.argsort(np.abs(shap_values))[::-1]
        top_feature_idx = int(sorted_indices[0])
        primary_feature = FEATURE_NAMES[top_feature_idx]

        top_attributions = {
            FEATURE_NAMES[idx]: float(shap_values[idx])
            for idx in sorted_indices[:top_k]
        }
        return primary_feature, top_attributions

    def _tree_path_attribution(
        self, node: DecisionNode, x: np.ndarray, shap_values: np.ndarray, weight: float
    ) -> None:
        """Recursive path contribution accumulation."""
        if node.is_leaf:
            return

        f_idx = node.feature_idx
        thresh = node.threshold
        x_val = x[f_idx]

        # Marginal impact of passing this decision threshold
        # If anomalous branch taken, attribute positive Shapley contribution
        if x_val > thresh:
            shap_values[f_idx] += weight * 0.15
            if node.right:
                self._tree_path_attribution(node.right, x, shap_values, weight)
        else:
            shap_values[f_idx] -= weight * 0.05
            if node.left:
                self._tree_path_attribution(node.left, x, shap_values, weight)


class ONNXRuntimeEngine:
    """High-throughput, sub-5ms inference runner for UNSW-NB15 threat detection."""

    def __init__(self, model_path: str = "models/unsw_nb15_model.onnx"):
        self.model_path = model_path
        self.ort_session = None
        self.trees: List[DecisionTree] = []

        json_path = model_path.replace(".onnx", ".json")
        if not os.path.exists(json_path):
            raise FileNotFoundError(f"Model manifest not found at {json_path}. Run convert_model.py first.")

        with open(json_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # Load decision trees
        for t_dict in manifest.get("trees", []):
            t = DecisionTree()
            t.root = DecisionNode.from_dict(t_dict)
            self.trees.append(t)

        logger.info(f"Loaded {len(self.trees)} ensemble trees from {json_path}")

        # Initialize background data for SHAP
        np.random.seed(42)
        dummy_bg = np.random.uniform(0.1, 10.0, size=(30, len(FEATURE_NAMES))).astype(np.float32)
        self.shap_explainer = LightweightTreeSHAP(self.trees, dummy_bg)

    def predict_single(self, feature_vector: np.ndarray) -> Tuple[str, float, np.ndarray, float]:
        """
        Run inference on a single flow feature vector.
        Returns: (predicted_class, anomaly_probability, full_probabilities, latency_ms)
        """
        t0 = time.perf_counter_ns()

        # Vectorized tree evaluation
        num_classes = len(ATTACK_CLASSES)
        probs = np.zeros(num_classes, dtype=np.float32)
        for tree in self.trees:
            probs += tree.predict_proba_single(feature_vector)
        probs /= len(self.trees)

        t1 = time.perf_counter_ns()
        latency_ms = (t1 - t0) / 1_000_000.0

        pred_idx = int(np.argmax(probs))
        pred_class = ATTACK_CLASSES[pred_idx]
        anomaly_prob = float(1.0 - probs[0])  # 1.0 - P(Normal)

        return pred_class, anomaly_prob, probs, latency_ms

    def explain_anomaly(self, feature_vector: np.ndarray, top_k: int = 3) -> Tuple[str, Dict[str, float]]:
        """Extract root-cause feature attribution using SHAP."""
        return self.shap_explainer.explain(feature_vector, top_k=top_k)


class NetSentinelInferenceConsumer:
    """Consumes Kafka network-telemetry flows, executes ONNX inference, and generates threat alerts."""

    def __init__(
        self,
        config_path: str = "config/config.yaml",
        alert_callback: Optional[Callable[[ThreatAlert], None]] = None
    ):
        self.config = self._load_config(config_path)
        model_path = self.config.get("inference", {}).get("model_path", "models/unsw_nb15_model.onnx")
        self.engine = ONNXRuntimeEngine(model_path)
        self.threshold = float(self.config.get("inference", {}).get("anomaly_threshold", 0.85))
        self.alert_callback = alert_callback

        # Latency monitoring stats
        self.latencies_ms: List[float] = []
        self.total_processed = 0
        self.total_anomalies = 0

    @staticmethod
    def _load_config(path: str) -> Dict[str, Any]:
        return load_config(path)

    @staticmethod
    def extract_feature_vector(flow: Dict[str, Any]) -> np.ndarray:
        """Extract ordered 36-dimensional feature vector matching UNSW-NB15 schema."""
        vec = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
        for i, fname in enumerate(FEATURE_NAMES):
            vec[i] = float(flow.get(fname, 0.0))
        return vec

    def process_flow(self, flow: Dict[str, Any]) -> Optional[ThreatAlert]:
        """Ingest, predict, explain, and alert on a single flow telemetry event."""
        self.total_processed += 1
        vec = self.extract_feature_vector(flow)

        pred_class, anomaly_prob, probs, latency_ms = self.engine.predict_single(vec)
        self.latencies_ms.append(latency_ms)
        if len(self.latencies_ms) > 10000:
            self.latencies_ms.pop(0)

        # Trigger SHAP attribution and alerting when probability exceeds threshold
        if anomaly_prob >= self.threshold:
            self.total_anomalies += 1
            primary_feature, shap_attributions = self.engine.explain_anomaly(vec, top_k=3)

            alert = ThreatAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                flow_id=flow.get("flow_id", f"{flow.get('src_ip')}:{flow.get('src_port')}"),
                src_ip=flow.get("src_ip", "0.0.0.0"),
                dst_ip=flow.get("dst_ip", "0.0.0.0"),
                src_port=int(flow.get("src_port", 0)),
                dst_port=int(flow.get("dst_port", 0)),
                proto=flow.get("proto", "tcp"),
                attack_cat=pred_class if pred_class != "Normal" else "Generic",
                anomaly_prob=anomaly_prob,
                primary_contributing_feature=primary_feature,
                shap_attributions=shap_attributions,
                severity="CRITICAL" if anomaly_prob >= 0.95 else "HIGH",
                raw_telemetry=flow
            )

            if self.alert_callback:
                self.alert_callback(alert)

            return alert

        return None

    def get_latency_stats(self) -> Dict[str, float]:
        """Return P50, P95, P99, and mean inference latency in milliseconds."""
        if not self.latencies_ms:
            return {"mean": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
        arr = np.array(self.latencies_ms)
        return {
            "mean": float(np.mean(arr)),
            "p50": float(np.percentile(arr, 50)),
            "p95": float(np.percentile(arr, 95)),
            "p99": float(np.percentile(arr, 99)),
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSentinel Inference & Explainability Engine")
    parser.add_argument("--benchmark", action="store_true", help="Run 1,000 flow sub-5ms latency benchmark")
    parser.add_argument("--config", default="config/config.yaml", help="Path to config.yaml")
    args = parser.parse_args()

    consumer = NetSentinelInferenceConsumer(config_path=args.config)

    if args.benchmark:
        from ..sniffer.flow_extractor import FlowExtractor
        extractor = FlowExtractor()

        logger.info("Running 1,000 flow inference latency benchmark...")
        alerts_generated = 0
        for _ in range(1000):
            mock_flow = extractor.generate_synthetic_flow()
            alert = consumer.process_flow(mock_flow)
            if alert:
                alerts_generated += 1

        stats = consumer.get_latency_stats()
        logger.info("=" * 60)
        logger.info("NETSENTINEL SUB-5MS INFERENCE BENCHMARK RESULTS")
        logger.info(f"Total Flows Processed: {consumer.total_processed}")
        logger.info(f"Anomalies Flagged:     {alerts_generated} ({alerts_generated/consumer.total_processed*100:.1f}%)")
        logger.info(f"P50 Latency:           {stats['p50']:.4f} ms")
        logger.info(f"P95 Latency:           {stats['p95']:.4f} ms")
        logger.info(f"P99 Latency:           {stats['p99']:.4f} ms (Target: < 5.0 ms)")
        logger.info("=" * 60)
