"""
NetSentinel - Alert Persistence Repository (SQLite & SQLAlchemy)

Provides ACID persistence for security alerts, enabling analyst status
transitions ('New', 'Investigating', 'Resolved'), notes, and CSV reporting.
"""
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

from src.alerts.schemas import AlertRecord, AlertSeverity, AlertStatus, SecurityFinding
from src.config import DATA_DIR

Base = declarative_base()


class AlertModel(Base):
    """SQLAlchemy ORM table for NetSentinel alert records."""
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, index=True)
    timestamp = Column(String(50), nullable=False)
    prediction = Column(Integer, nullable=False)
    label = Column(String(20), nullable=False)
    probability_attack = Column(Float, nullable=True)
    confidence = Column(Float, nullable=False)
    is_alert = Column(Boolean, nullable=False, default=True)
    severity = Column(String(20), nullable=False)
    model_name = Column(String(100), nullable=False)
    threshold_used = Column(Float, nullable=False)
    features_summary_json = Column(Text, nullable=False, default="{}")
    status = Column(String(20), nullable=False, default=AlertStatus.NEW.value, index=True)
    analyst_notes = Column(Text, nullable=True, default="")
    updated_at = Column(String(50), nullable=False)


class AlertRepository:
    """Repository managing local SQLite storage and queries for security alerts."""

    def __init__(self, db_url: Optional[str] = None):
        if db_url is None:
            db_path = DATA_DIR / "netsentinel.db"
            self.db_url = f"sqlite:///{db_path}"
        else:
            self.db_url = db_url

        self.engine = create_engine(self.db_url, connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def _to_record(self, model: AlertModel) -> AlertRecord:
        """Converts an ORM model to a Pydantic AlertRecord."""
        features_dict = {}
        if model.features_summary_json:
            try:
                features_dict = json.loads(model.features_summary_json)
            except Exception:
                features_dict = {}

        return AlertRecord(
            finding_id=model.id,
            timestamp=model.timestamp,
            prediction=model.prediction,
            label=model.label,
            probability_attack=model.probability_attack,
            confidence=model.confidence,
            is_alert=model.is_alert,
            severity=AlertSeverity(model.severity),
            model_name=model.model_name,
            threshold_used=model.threshold_used,
            features_summary=features_dict,
            status=AlertStatus(model.status),
            analyst_notes=model.analyst_notes or "",
            updated_at=model.updated_at,
        )

    def save_finding_as_alert(
        self,
        finding: SecurityFinding,
        status: AlertStatus = AlertStatus.NEW,
        notes: str = "",
    ) -> AlertRecord:
        """Persists a SecurityFinding as an AlertRecord."""
        now_iso = datetime.now(timezone.utc).isoformat()
        db_model = AlertModel(
            id=finding.finding_id,
            timestamp=finding.timestamp,
            prediction=finding.prediction,
            label=finding.label,
            probability_attack=finding.probability_attack,
            confidence=finding.confidence,
            is_alert=finding.is_alert,
            severity=finding.severity.value,
            model_name=finding.model_name,
            threshold_used=finding.threshold_used,
            features_summary_json=json.dumps(finding.features_summary),
            status=status.value,
            analyst_notes=notes,
            updated_at=now_iso,
        )
        with self.SessionLocal() as session:
            merged = session.merge(db_model)
            session.commit()
            session.refresh(merged)
            return self._to_record(merged)

    def get_alert_by_id(self, alert_id: str) -> Optional[AlertRecord]:
        """Retrieves a single alert by its unique UUID."""
        with self.SessionLocal() as session:
            model = session.query(AlertModel).filter(AlertModel.id == alert_id).first()
            if model:
                return self._to_record(model)
            return None

    def list_alerts(
        self,
        status: Optional[Union[AlertStatus, str]] = None,
        severity: Optional[Union[AlertSeverity, str]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AlertRecord]:
        """Lists alerts with optional status and severity filtering."""
        with self.SessionLocal() as session:
            query = session.query(AlertModel)
            if status:
                val = status.value if isinstance(status, AlertStatus) else str(status)
                query = query.filter(AlertModel.status == val)
            if severity:
                val = severity.value if isinstance(severity, AlertSeverity) else str(severity)
                query = query.filter(AlertModel.severity == val)

            models = query.order_by(AlertModel.timestamp.desc()).offset(offset).limit(limit).all()
            return [self._to_record(m) for m in models]

    def update_alert(
        self,
        alert_id: str,
        status: Optional[AlertStatus] = None,
        analyst_notes: Optional[str] = None,
    ) -> Optional[AlertRecord]:
        """Updates alert investigation status or appends analyst notes."""
        with self.SessionLocal() as session:
            model = session.query(AlertModel).filter(AlertModel.id == alert_id).first()
            if not model:
                return None

            if status is not None:
                model.status = status.value if isinstance(status, AlertStatus) else str(status)
            if analyst_notes is not None:
                model.analyst_notes = analyst_notes
            model.updated_at = datetime.now(timezone.utc).isoformat()

            session.commit()
            session.refresh(model)
            return self._to_record(model)

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Aggregates alert metrics for the analyst dashboard and reporting."""
        with self.SessionLocal() as session:
            total = session.query(AlertModel).count()
            new_count = session.query(AlertModel).filter(AlertModel.status == AlertStatus.NEW.value).count()
            investigating_count = session.query(AlertModel).filter(AlertModel.status == AlertStatus.INVESTIGATING.value).count()
            resolved_count = session.query(AlertModel).filter(AlertModel.status == AlertStatus.RESOLVED.value).count()
            critical_count = session.query(AlertModel).filter(AlertModel.severity == AlertSeverity.CRITICAL.value).count()
            high_count = session.query(AlertModel).filter(AlertModel.severity == AlertSeverity.HIGH.value).count()

            return {
                "total_alerts": total,
                "status_breakdown": {
                    "New": new_count,
                    "Investigating": investigating_count,
                    "Resolved": resolved_count,
                },
                "high_priority_count": critical_count + high_count,
            }

    def export_alerts_to_csv(self, output_path: Union[str, Path]) -> Path:
        """Exports all alerts to a clean CSV report for SOC reporting."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        alerts = self.list_alerts(limit=10000)
        fieldnames = [
            "finding_id", "timestamp", "prediction", "label",
            "probability_attack", "confidence", "severity", "status",
            "model_name", "analyst_notes", "updated_at"
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for a in alerts:
                row = a.model_dump()
                row.pop("features_summary", None)
                row.pop("is_alert", None)
                row.pop("threshold_used", None)
                writer.writerow(row)

        return output_path
