"""
NetSentinel - FastAPI REST API Application

Exposes endpoints for health checks, live flow inference, batch scoring,
and Security Operations Center (SOC) alert triage.
"""
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from src.alerts.repository import AlertRepository
from src.alerts.schemas import (
    AlertRecord,
    AlertSeverity,
    AlertStatus,
    AlertUpdate,
    BatchTrafficInput,
    SecurityFinding,
    TrafficFlowInput,
)
from src.config import REPORTS_DIR
from src.detection.service import DetectionService

# Initialize FastAPI app
app = FastAPI(
    title="NetSentinel - Network Intrusion Detection System API",
    description=(
        "Defensive network intrusion detection and security alert triage API. "
        "Transforms network flows, detects malicious anomalies using machine learning, "
        "and tracks SOC investigation lifecycles."
    ),
    version="1.0.0",
)

# Enable CORS for local dashboards and testing tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global services (initialized lazily or at module load)
_detection_service: Optional[DetectionService] = None
_alert_repo: Optional[AlertRepository] = None


def get_detection_service() -> DetectionService:
    global _detection_service
    if _detection_service is None:
        _detection_service = DetectionService()
    return _detection_service


def get_alert_repository() -> AlertRepository:
    global _alert_repo
    if _alert_repo is None:
        _alert_repo = AlertRepository()
    return _alert_repo


@app.get("/", tags=["General"])
def root() -> Dict[str, str]:
    """Root endpoint welcoming users and providing documentation link."""
    return {
        "system": "NetSentinel Network Intrusion Detection API",
        "status": "operational",
        "docs_url": "/docs",
        "health_url": "/health",
    }


@app.get("/health", tags=["Health"])
def health_check() -> Dict[str, Any]:
    """
    Health check endpoint reporting model and preprocessor readiness.
    """
    try:
        service = get_detection_service()
        health = service.health_check()
        return health
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Detection service unavailable: {str(e)}",
        )


@app.get("/model/info", tags=["Model"])
def model_info() -> Dict[str, Any]:
    """Returns active model metadata, feature contract, and default threshold."""
    service = get_detection_service()
    return service.get_service_info()


@app.post("/predict", response_model=SecurityFinding, tags=["Detection"])
def predict_flow(
    flow: TrafficFlowInput,
    save_alert: bool = Query(True, description="Whether to automatically store alerts in the SOC repository"),
    threshold: Optional[float] = Query(None, ge=0.0, le=1.0, description="Optional custom decision threshold"),
) -> SecurityFinding:
    """
    Performs real-time intrusion detection inference on a single network flow record.
    If the flow is flagged as malicious (is_alert=True) and save_alert=True,
    it is automatically registered in the Alert Management repository.
    """
    try:
        service = get_detection_service()
        finding = service.detect_flow(flow, threshold=threshold)

        if finding.is_alert and save_alert:
            repo = get_alert_repository()
            repo.save_finding_as_alert(finding)

        return finding
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Inference error: {str(e)}")


@app.post("/predict/batch", response_model=List[SecurityFinding], tags=["Detection"])
def predict_batch(
    batch: BatchTrafficInput,
    save_alerts: bool = Query(True, description="Whether to automatically store alerts in the SOC repository"),
    threshold: Optional[float] = Query(None, ge=0.0, le=1.0, description="Optional custom decision threshold"),
) -> List[SecurityFinding]:
    """
    Processes a batch of traffic flow records and returns a list of SecurityFindings.
    """
    try:
        service = get_detection_service()
        findings = service.detect_batch(batch.flows, threshold=threshold)

        if save_alerts:
            repo = get_alert_repository()
            for f in findings:
                if f.is_alert:
                    repo.save_finding_as_alert(f)

        return findings
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Batch error: {str(e)}")


@app.get("/alerts", response_model=List[AlertRecord], tags=["Alert Management"])
def list_alerts(
    status_filter: Optional[AlertStatus] = Query(None, alias="status", description="Filter by lifecycle status"),
    severity_filter: Optional[AlertSeverity] = Query(None, alias="severity", description="Filter by alert severity"),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of alerts to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
) -> List[AlertRecord]:
    """Lists security alerts with optional filtering for SOC analysts."""
    repo = get_alert_repository()
    return repo.list_alerts(status=status_filter, severity=severity_filter, limit=limit, offset=offset)


@app.get("/alerts/stats", tags=["Alert Management"])
def alert_stats() -> Dict[str, Any]:
    """Returns SOC metric summaries (total, New, Investigating, Resolved, high priority count)."""
    repo = get_alert_repository()
    return repo.get_alert_statistics()


@app.get("/alerts/{alert_id}", response_model=AlertRecord, tags=["Alert Management"])
def get_alert(alert_id: str) -> AlertRecord:
    """Retrieves full details and evidence for a specific alert."""
    repo = get_alert_repository()
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")
    return alert


@app.patch("/alerts/{alert_id}", response_model=AlertRecord, tags=["Alert Management"])
def update_alert(alert_id: str, update: AlertUpdate) -> AlertRecord:
    """Updates the investigation status (New -> Investigating -> Resolved) or analyst notes."""
    repo = get_alert_repository()
    updated = repo.update_alert(alert_id, status=update.status, analyst_notes=update.analyst_notes)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")
    return updated


@app.get("/alerts/export/csv", tags=["Reporting"])
def export_alerts_csv() -> FileResponse:
    """Exports all recorded alerts to a CSV report file for auditing and offline analysis."""
    repo = get_alert_repository()
    export_path = REPORTS_DIR / "exported_alerts.csv"
    repo.export_alerts_to_csv(export_path)

    return FileResponse(
        path=str(export_path),
        filename="netsentinel_alerts_report.csv",
        media_type="text/csv",
    )
