"""
NetSentinel - Automated Unit Tests for Alert Management & Persistence
"""
from pathlib import Path
import pytest

from src.alerts.repository import AlertRepository
from src.alerts.schemas import AlertRecord, AlertSeverity, AlertStatus, SecurityFinding


@pytest.fixture
def temp_alert_repo(tmp_path):
    """Instantiates an AlertRepository using an isolated SQLite database."""
    db_file = tmp_path / "test_alerts.db"
    repo = AlertRepository(db_url=f"sqlite:///{db_file}")
    return repo


@pytest.fixture
def sample_security_finding():
    """Generates a representative SecurityFinding."""
    return SecurityFinding(
        finding_id="12345678-1234-5678-1234-567812345678",
        timestamp="2026-09-25T12:00:00Z",
        prediction=1,
        label="Attack",
        probability_attack=0.885,
        confidence=0.885,
        is_alert=True,
        severity=AlertSeverity.HIGH,
        model_name="DecisionTreeClassifier",
        threshold_used=0.5,
        features_summary={"proto": "tcp", "service": "http", "sbytes": 1024},
    )


def test_save_and_retrieve_alert(temp_alert_repo, sample_security_finding):
    """Verify an alert can be created and fetched by its finding_id."""
    saved = temp_alert_repo.save_finding_as_alert(sample_security_finding, notes="Initial triage")

    assert saved.finding_id == sample_security_finding.finding_id
    assert saved.status == AlertStatus.NEW
    assert saved.analyst_notes == "Initial triage"
    assert saved.severity == AlertSeverity.HIGH

    fetched = temp_alert_repo.get_alert_by_id(sample_security_finding.finding_id)
    assert fetched is not None
    assert fetched.label == "Attack"
    assert fetched.features_summary.get("proto") == "tcp"


def test_list_alerts_and_filtering(temp_alert_repo, sample_security_finding):
    """Verify alerts can be listed and filtered by status and severity."""
    temp_alert_repo.save_finding_as_alert(sample_security_finding, status=AlertStatus.NEW)

    second_finding = sample_security_finding.model_copy(
        update={"finding_id": "87654321-4321-8765-4321-876543210987", "severity": AlertSeverity.LOW}
    )
    temp_alert_repo.save_finding_as_alert(second_finding, status=AlertStatus.RESOLVED)

    all_alerts = temp_alert_repo.list_alerts()
    assert len(all_alerts) == 2

    new_alerts = temp_alert_repo.list_alerts(status=AlertStatus.NEW)
    assert len(new_alerts) == 1
    assert new_alerts[0].finding_id == sample_security_finding.finding_id

    resolved_alerts = temp_alert_repo.list_alerts(status=AlertStatus.RESOLVED)
    assert len(resolved_alerts) == 1

    high_alerts = temp_alert_repo.list_alerts(severity=AlertSeverity.HIGH)
    assert len(high_alerts) == 1


def test_update_alert_status_and_notes(temp_alert_repo, sample_security_finding):
    """Verify analyst can update triage status and notes."""
    temp_alert_repo.save_finding_as_alert(sample_security_finding)

    updated = temp_alert_repo.update_alert(
        alert_id=sample_security_finding.finding_id,
        status=AlertStatus.INVESTIGATING,
        analyst_notes="Escalated to Tier 2 SOC analyst",
    )

    assert updated is not None
    assert updated.status == AlertStatus.INVESTIGATING
    assert updated.analyst_notes == "Escalated to Tier 2 SOC analyst"

    # Verify persistence
    fetched = temp_alert_repo.get_alert_by_id(sample_security_finding.finding_id)
    assert fetched.status == AlertStatus.INVESTIGATING
    assert fetched.analyst_notes == "Escalated to Tier 2 SOC analyst"


def test_alert_statistics(temp_alert_repo, sample_security_finding):
    """Verify aggregation metrics for the dashboard."""
    temp_alert_repo.save_finding_as_alert(sample_security_finding)
    stats = temp_alert_repo.get_alert_statistics()

    assert stats["total_alerts"] == 1
    assert stats["status_breakdown"]["New"] == 1
    assert stats["high_priority_count"] == 1


def test_export_alerts_to_csv(temp_alert_repo, sample_security_finding, tmp_path):
    """Verify exporting alerts to a readable CSV report."""
    temp_alert_repo.save_finding_as_alert(sample_security_finding)
    csv_file = tmp_path / "alerts_export.csv"

    out = temp_alert_repo.export_alerts_to_csv(csv_file)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert sample_security_finding.finding_id in content
    assert "Attack" in content
