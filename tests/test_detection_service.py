"""
NetSentinel - Automated Unit Tests for DetectionService Layer
"""
import pandas as pd
import pytest

from src.alerts.schemas import AlertSeverity, TrafficFlowInput
from src.config import NUMERICAL_FEATURES
from src.detection.service import DetectionService


@pytest.fixture
def service():
    """Initializes the DetectionService."""
    return DetectionService()


@pytest.fixture
def sample_flow_dict():
    """Generates a valid single flow dictionary."""
    flow = {
        "proto": "tcp",
        "service": "http",
        "state": "FIN",
    }
    for f in NUMERICAL_FEATURES:
        flow[f] = 5.0
    return flow


def test_service_initialization(service):
    """Verify DetectionService initializes cleanly with model and preprocessor."""
    info = service.get_service_info()
    assert info["status"] == "online"
    assert info["model_name"] != "Unknown"
    assert info["expected_raw_features_count"] == 42


def test_detect_flow_dict_input(service, sample_flow_dict):
    """Verify detection on raw dictionary input."""
    finding = service.detect_flow(sample_flow_dict)
    assert finding.prediction in (0, 1)
    assert finding.label in ("Normal", "Attack")
    assert 0.0 <= finding.confidence <= 1.0
    assert finding.severity in AlertSeverity
    assert "proto" in finding.features_summary


def test_detect_flow_pydantic_input(service, sample_flow_dict):
    """Verify detection accepts Pydantic TrafficFlowInput model directly."""
    flow_obj = TrafficFlowInput(**sample_flow_dict)
    finding = service.detect_flow(flow_obj)
    assert finding.prediction in (0, 1)


def test_detect_flow_unseen_categories(service, sample_flow_dict):
    """Verify that unseen categories (e.g. proto='unknownproto', state='ACC') do not crash."""
    sample_flow_dict["proto"] = "unknownproto_xyz"
    sample_flow_dict["state"] = "ACC"
    finding = service.detect_flow(sample_flow_dict)
    assert finding.prediction in (0, 1)


def test_detect_flow_custom_threshold(service, sample_flow_dict):
    """Verify custom decision threshold is respected."""
    # With threshold 0.0, everything is flagged as attack
    finding_low = service.detect_flow(sample_flow_dict, threshold=0.0)
    assert finding_low.is_alert is True
    assert finding_low.threshold_used == 0.0

    # With threshold 1.0, nothing is flagged as attack
    finding_high = service.detect_flow(sample_flow_dict, threshold=1.0)
    assert finding_high.is_alert is False
    assert finding_high.threshold_used == 1.0


def test_detect_batch_dataframe(service, sample_flow_dict):
    """Verify batch detection over a pandas DataFrame."""
    df_batch = pd.DataFrame([sample_flow_dict, sample_flow_dict])
    findings = service.detect_batch(df_batch)
    assert len(findings) == 2
    assert findings[0].prediction in (0, 1)


def test_detect_flow_missing_features_raises_error(service):
    """Verify ValueError is raised if mandatory features are omitted."""
    incomplete = {"proto": "tcp", "service": "http"}
    with pytest.raises(ValueError, match="Missing required flow features"):
        service.detect_flow(incomplete)
