"""
NetSentinel - Reusable Detection Service Layer

Coordinates preprocessor transformation, model inference, and structured
SecurityFinding generation.
"""
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

import numpy as np
import pandas as pd

from src.alerts.schemas import AlertSeverity, SecurityFinding, TrafficFlowInput
from src.config import (
    DEFAULT_DETECTION_THRESHOLD,
    EXPECTED_RAW_FEATURES,
    MODEL_PATH,
    PREPROCESSOR_PATH,
)
from src.data.preprocessing import clean_raw_dataframe, load_preprocessor_bundle
from src.detection.train import load_model_bundle


class DetectionService:
    """
    Core NetSentinel Detection Service.
    Loads trained model and preprocessor artifacts, applies validated
    transformations, and generates structured security findings.
    """

    def __init__(
        self,
        model_path: Union[str, Path] = MODEL_PATH,
        preprocessor_path: Union[str, Path] = PREPROCESSOR_PATH,
        default_threshold: float = 0.5,
    ):
        self.model_path = Path(model_path)
        self.preprocessor_path = Path(preprocessor_path)
        self.default_threshold = float(default_threshold)

        # Artifact holders
        self.preprocessor: Optional[Any] = None
        self.model: Optional[Any] = None
        self.model_name: str = "Unknown"
        self.model_metadata: Dict[str, Any] = {}
        self.preprocessor_metadata: Dict[str, Any] = {}

        self.load_artifacts()

    def load_artifacts(self) -> None:
        """Loads both the preprocessor bundle and the model bundle from disk."""
        # Load Preprocessor
        if not self.preprocessor_path.exists():
            raise FileNotFoundError(f"Preprocessor artifact not found at {self.preprocessor_path}")
        prep_bundle = load_preprocessor_bundle(self.preprocessor_path)
        self.preprocessor = prep_bundle["preprocessor"]
        self.preprocessor_metadata = prep_bundle.get("metadata", {})

        # Load Model
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model artifact not found at {self.model_path}")
        model_bundle = load_model_bundle(self.model_path)
        self.model = model_bundle["model"]
        self.model_name = model_bundle.get("model_name", self.model.__class__.__name__)
        self.model_metadata = model_bundle.get("metadata", {})

    def _determine_severity(self, is_alert: bool, probability_attack: Optional[float]) -> AlertSeverity:
        """
        Objectively derives severity from model confidence score:
        - Normal flows: INFORMATIONAL
        - Alerts:
          - probability >= 0.90: CRITICAL (extreme confidence of intrusion)
          - probability >= 0.75: HIGH
          - probability >= 0.60: MEDIUM
          - otherwise: LOW
        """
        if not is_alert:
            return AlertSeverity.INFORMATIONAL

        prob = probability_attack if probability_attack is not None else 1.0

        if prob >= 0.90:
            return AlertSeverity.CRITICAL
        elif prob >= 0.75:
            return AlertSeverity.HIGH
        elif prob >= 0.60:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def _extract_evidence_summary(self, raw_flow: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts key flow indicators as evidence for security analysts."""
        evidence_keys = [
            "proto", "service", "state", "dur", "spkts", "dpkts",
            "sbytes", "dbytes", "rate", "sttl", "dttl"
        ]
        return {k: raw_flow.get(k) for k in evidence_keys if k in raw_flow}

    def detect_flow(
        self,
        raw_flow: Union[Dict[str, Any], TrafficFlowInput],
        threshold: Optional[float] = None,
    ) -> SecurityFinding:
        """
        Processes a single flow record and returns a SecurityFinding.
        """
        if isinstance(raw_flow, TrafficFlowInput):
            flow_dict = raw_flow.model_dump()
        elif isinstance(raw_flow, dict):
            flow_dict = raw_flow.copy()
        else:
            raise TypeError(f"Expected dict or TrafficFlowInput, got {type(raw_flow)}")

        # Validate that required features are present
        missing = [f for f in EXPECTED_RAW_FEATURES if f not in flow_dict]
        if missing:
            raise ValueError(f"Missing required flow features: {missing}")

        thresh = float(threshold) if threshold is not None else self.default_threshold

        # Build clean 1-row DataFrame strictly with expected features
        df_row = pd.DataFrame([{f: flow_dict[f] for f in EXPECTED_RAW_FEATURES}])
        df_clean = clean_raw_dataframe(df_row)
        X_trans = self.preprocessor.transform(df_clean[EXPECTED_RAW_FEATURES])

        # Inference
        has_proba = hasattr(self.model, "predict_proba")
        if has_proba:
            probs = self.model.predict_proba(X_trans)[0]
            prob_attack = float(probs[1])
            predicted_label = int(prob_attack >= thresh)
            confidence = prob_attack if predicted_label == 1 else float(probs[0])
        else:
            predicted_label = int(self.model.predict(X_trans)[0])
            prob_attack = 1.0 if predicted_label == 1 else 0.0
            confidence = 1.0

        is_alert = bool(predicted_label == 1)
        severity = self._determine_severity(is_alert, prob_attack if has_proba else None)

        return SecurityFinding(
            finding_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            prediction=predicted_label,
            label="Attack" if predicted_label == 1 else "Normal",
            probability_attack=round(prob_attack, 4) if has_proba else None,
            confidence=round(confidence, 4),
            is_alert=is_alert,
            severity=severity,
            model_name=self.model_name,
            threshold_used=thresh,
            features_summary=self._extract_evidence_summary(flow_dict),
        )

    def detect_batch(
        self,
        flows: Union[List[Dict[str, Any]], List[TrafficFlowInput], pd.DataFrame],
        threshold: Optional[float] = None,
    ) -> List[SecurityFinding]:
        """
        Processes a batch of flow records and returns a list of SecurityFindings.
        """
        if isinstance(flows, pd.DataFrame):
            records = flows.to_dict(orient="records")
        elif isinstance(flows, list):
            records = [f.model_dump() if isinstance(f, TrafficFlowInput) else f for f in flows]
        else:
            raise TypeError("Expected list of dicts/TrafficFlowInput or pd.DataFrame")

        if not records:
            return []

        # Validate first row to catch schema errors early
        missing = [f for f in EXPECTED_RAW_FEATURES if f not in records[0]]
        if missing:
            raise ValueError(f"Batch records are missing required flow features: {missing}")

        thresh = float(threshold) if threshold is not None else self.default_threshold

        df_batch = pd.DataFrame(records)
        df_clean = clean_raw_dataframe(df_batch[EXPECTED_RAW_FEATURES])
        X_trans = self.preprocessor.transform(df_clean[EXPECTED_RAW_FEATURES])

        has_proba = hasattr(self.model, "predict_proba")
        if has_proba:
            probs = self.model.predict_proba(X_trans)
            prob_attacks = probs[:, 1]
            predictions = (prob_attacks >= thresh).astype(int)
            confidences = np.where(predictions == 1, prob_attacks, probs[:, 0])
        else:
            predictions = self.model.predict(X_trans).astype(int)
            prob_attacks = predictions.astype(float)
            confidences = np.ones(len(predictions))

        findings: List[SecurityFinding] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for idx, row_dict in enumerate(records):
            pred = int(predictions[idx])
            p_att = float(prob_attacks[idx]) if has_proba else None
            conf = float(confidences[idx])
            is_alt = bool(pred == 1)
            sev = self._determine_severity(is_alt, p_att)

            findings.append(
                SecurityFinding(
                    finding_id=str(uuid4()),
                    timestamp=now_iso,
                    prediction=pred,
                    label="Attack" if pred == 1 else "Normal",
                    probability_attack=round(p_att, 4) if p_att is not None else None,
                    confidence=round(conf, 4),
                    is_alert=is_alt,
                    severity=sev,
                    model_name=self.model_name,
                    threshold_used=thresh,
                    features_summary=self._extract_evidence_summary(row_dict),
                )
            )

        return findings

    def get_service_info(self) -> Dict[str, Any]:
        """Returns service status, loaded model information, and feature schema."""
        return {
            "status": "online",
            "model_name": self.model_name,
            "model_path": str(self.model_path),
            "preprocessor_path": str(self.preprocessor_path),
            "default_threshold": self.default_threshold,
            "expected_raw_features_count": len(EXPECTED_RAW_FEATURES),
            "model_metadata": self.model_metadata,
        }

    def health_check(self) -> Dict[str, Any]:
        """Runs a minimal internal validation check."""
        # Create minimal dummy flow to verify end-to-end inference
        dummy_flow = {"proto": "tcp", "service": "http", "state": "FIN"}
        from src.config import NUMERICAL_FEATURES
        for f in NUMERICAL_FEATURES:
            dummy_flow[f] = 0.0

        finding = self.detect_flow(dummy_flow)
        return {
            "status": "healthy",
            "model_loaded": self.model is not None,
            "preprocessor_loaded": self.preprocessor is not None,
            "model_name": self.model_name,
            "smoke_test_passed": finding.prediction in (0, 1),
        }
