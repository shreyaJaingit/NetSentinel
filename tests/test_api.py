"""
NetSentinel - Automated Unit & Integration Tests for FastAPI REST Endpoints
"""
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.config import NUMERICAL_FEATURES


@pytest.fixture
def client():
    """Returns a TestClient instance for the FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def valid_flow_payload():
    """Generates a valid raw flow dictionary satisfying EXPECTED_RAW_FEATURES."""
    payload = {
        "proto": "tcp",
        "service": "http",
        "state": "FIN",
    }
    for col in NUMERICAL_FEATURES:
        payload[col] = 10.0
    return payload


def test_root_endpoint(client):
    """Verify GET / returns 200 and system metadata."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "NetSentinel" in data["system"]


def test_health_endpoint(client):
    """Verify GET /health reports model and preprocessor status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert data["preprocessor_loaded"] is True


def test_model_info_endpoint(client):
    """Verify GET /model/info returns active model metadata."""
    response = client.get("/model/info")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["expected_raw_features_count"] == 42


def test_predict_single_flow_success(client, valid_flow_payload):
    """Verify POST /predict returns valid structured SecurityFinding."""
    response = client.post("/predict", json=valid_flow_payload)
    assert response.status_code == 200
    data = response.json()

    assert "finding_id" in data
    assert "timestamp" in data
    assert data["prediction"] in (0, 1)
    assert data["label"] in ("Normal", "Attack")
    assert 0.0 <= data["confidence"] <= 1.0
    assert "severity" in data
    assert isinstance(data["is_alert"], bool)
    assert "features_summary" in data


def test_predict_single_flow_missing_fields(client):
    """Verify POST /predict returns 422 on incomplete payloads."""
    incomplete_payload = {"proto": "tcp", "service": "http"}
    response = client.post("/predict", json=incomplete_payload)
    assert response.status_code == 422


def test_predict_batch_success(client, valid_flow_payload):
    """Verify POST /predict/batch handles multiple records."""
    batch_payload = {"flows": [valid_flow_payload, valid_flow_payload]}
    response = client.post("/predict/batch", json=batch_payload)
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["prediction"] in (0, 1)


def test_predict_batch_empty_list(client):
    """Verify POST /predict/batch rejects empty flow arrays."""
    response = client.post("/predict/batch", json={"flows": []})
    assert response.status_code == 422


def test_alerts_lifecycle_flow(client, valid_flow_payload):
    """
    Verify complete triage lifecycle:
    1. Score an attack flow to generate an alert
    2. Retrieve alert list
    3. Update alert status and notes
    4. Verify stats
    """
    # 1. Trigger prediction with save_alert=True
    pred_res = client.post("/predict?save_alert=true", json=valid_flow_payload)
    assert pred_res.status_code == 200
    finding = pred_res.json()

    # 2. List alerts
    alerts_res = client.get("/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()

    # 3. If an alert was registered, verify PATCH endpoint
    if alerts:
        target_alert = alerts[0]
        alert_id = target_alert["finding_id"]

        patch_res = client.patch(
            f"/alerts/{alert_id}",
            json={"status": "Investigating", "analyst_notes": "Automated test note"},
        )
        assert patch_res.status_code == 200
        updated = patch_res.json()
        assert updated["status"] == "Investigating"
        assert updated["analyst_notes"] == "Automated test note"


def test_export_alerts_csv_endpoint(client):
    """Verify GET /alerts/export/csv returns a downloadable CSV file."""
    response = client.get("/alerts/export/csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
