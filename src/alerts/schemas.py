"""
NetSentinel - Alert & Detection Schema Definitions (Pydantic Models)
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class AlertStatus(str, Enum):
    NEW = "New"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"


class AlertSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TrafficFlowInput(BaseModel):
    """
    Schema for raw input traffic flows.
    Requires all 42 network flow features with strict validation.
    """
    model_config = ConfigDict(extra="ignore")

    # Categoricals
    proto: str = Field(..., description="Transport/Network protocol (e.g. tcp, udp, arp)")
    service: str = Field(..., description="Application service (e.g. http, dns, or '-' if none)")
    state: str = Field(..., description="Connection state (e.g. FIN, CON, INT)")

    # 39 Numerical flow metrics
    dur: float = Field(..., description="Record total duration in seconds")
    spkts: float = Field(..., description="Source-to-destination packet count")
    dpkts: float = Field(..., description="Destination-to-source packet count")
    sbytes: float = Field(..., description="Source-to-destination byte count")
    dbytes: float = Field(..., description="Destination-to-source byte count")
    rate: float = Field(..., description="Packets per second")
    sttl: float = Field(..., description="Source-to-destination time-to-live")
    dttl: float = Field(..., description="Destination-to-source time-to-live")
    sload: float = Field(..., description="Source bits per second")
    dload: float = Field(..., description="Destination bits per second")
    sloss: float = Field(..., description="Source packets retransmitted or dropped")
    dloss: float = Field(..., description="Destination packets retransmitted or dropped")
    sinpkt: float = Field(..., description="Source interpacket arrival time (msec)")
    dinpkt: float = Field(..., description="Destination interpacket arrival time (msec)")
    sjit: float = Field(..., description="Source jitter (msec)")
    djit: float = Field(..., description="Destination jitter (msec)")
    swin: float = Field(..., description="Source TCP window advertisement value")
    stcpb: float = Field(..., description="Source TCP base sequence number")
    dtcpb: float = Field(..., description="Destination TCP base sequence number")
    dwin: float = Field(..., description="Destination TCP window advertisement value")
    tcprtt: float = Field(..., description="TCP round-trip time (msec)")
    synack: float = Field(..., description="TCP SYN to SYN-ACK time (msec)")
    ackdat: float = Field(..., description="TCP SYN-ACK to ACK time (msec)")
    smean: float = Field(..., description="Mean packet size transmitted by source")
    dmean: float = Field(..., description="Mean packet size transmitted by destination")
    trans_depth: float = Field(..., description="Pipelined HTTP request depth")
    response_body_len: float = Field(..., description="Actual uncompressed response body length")
    ct_srv_src: float = Field(..., description="Connections to same service from source in last 100")
    ct_state_ttl: float = Field(..., description="Connections with same state and TTL")
    ct_dst_ltm: float = Field(..., description="Connections to destination address in last 100")
    ct_src_dport_ltm: float = Field(..., description="Connections from source to destination port")
    ct_dst_sport_ltm: float = Field(..., description="Connections from dest to source port")
    ct_dst_src_ltm: float = Field(..., description="Connections between source and destination")
    is_ftp_login: float = Field(..., description="1 if FTP session logged in, 0 otherwise")
    ct_ftp_cmd: float = Field(..., description="Count of commands executed in FTP session")
    ct_flw_http_mthd: float = Field(..., description="Count of HTTP methods in flow")
    ct_src_ltm: float = Field(..., description="Connections from source address in last 100")
    ct_srv_dst: float = Field(..., description="Connections to same service to destination")
    is_sm_ips_ports: float = Field(..., description="1 if source and destination IP & port match")


class BatchTrafficInput(BaseModel):
    flows: List[TrafficFlowInput] = Field(..., min_length=1, description="List of traffic flow records to analyze")


class SecurityFinding(BaseModel):
    """
    Structured security detection finding produced by the detection pipeline.
    """
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    prediction: int = Field(..., description="Binary prediction: 0 (Normal) or 1 (Attack)")
    label: str = Field(..., description="Predicted label string: 'Normal' or 'Attack'")
    probability_attack: Optional[float] = Field(None, description="Model-estimated attack probability")
    confidence: float = Field(..., description="Prediction confidence score")
    is_alert: bool = Field(..., description="True if flow is flagged as suspicious/malicious")
    severity: AlertSeverity = Field(..., description="Objectively assigned severity based on confidence")
    model_name: str = Field(..., description="Identifier of the model used for inference")
    threshold_used: float = Field(0.5, description="Decision threshold applied")
    features_summary: Dict[str, Any] = Field(default_factory=dict, description="Key flow metrics for analyst evidence")


class AlertRecord(SecurityFinding):
    """
    Alert record as persisted in the NetSentinel alert management repository.
    """
    status: AlertStatus = Field(default=AlertStatus.NEW, description="Triage lifecycle status")
    analyst_notes: Optional[str] = Field(default="", description="Investigation notes recorded by security analyst")
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AlertUpdate(BaseModel):
    """
    Schema for analyst status transitions and notes.
    """
    status: Optional[AlertStatus] = None
    analyst_notes: Optional[str] = None
