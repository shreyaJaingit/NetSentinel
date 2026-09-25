"""
NetSentinel - Security Analyst Dashboard & SOC Investigation Console (Streamlit)

Provides security analysts with an interactive interface for:
- Live network flow inspection and classification
- SOC Alert triage, status transitions, and notes
- Model evaluation transparency and confusion matrix review
- CSV report exporting
"""
import json
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st

from src.alerts.repository import AlertRepository
from src.alerts.schemas import AlertSeverity, AlertStatus, TrafficFlowInput
from src.config import (
    NUMERICAL_FEATURES,
    REPORTS_DIR,
    TEST_DATA_PATH,
)
from src.detection.service import DetectionService

# Page Setup
st.set_page_config(
    page_title="NetSentinel - Security Analyst Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_resource
def get_services():
    """Initializes and caches detection service and alert repository."""
    service = DetectionService()
    repo = AlertRepository()
    return service, repo


service, repo = get_services()

# Header & Educational / Ethical Notice
st.title("🛡️ NetSentinel: Network Intrusion Detection & Investigation Console")
st.markdown(
    """
    > **⚠️ Security & ML Operations Notice**: NetSentinel uses trained machine learning classifiers 
    > for defensive flow anomaly detection. Model confidence scores reflect statistical likelihood, 
    > **not proof of compromise**, and always require human analyst validation before operational response.
    """
)

# Sidebar
st.sidebar.image("https://img.shields.io/badge/NetSentinel-Defense_Active-blue?style=for-the-badge&logo=shield", use_container_width=True)
st.sidebar.subheader("System Status")
info = service.get_service_info()
st.sidebar.success(f"**Model**: {info['model_name']}")
st.sidebar.info(f"**Engine**: Scikit-Learn Pipeline ({info['expected_raw_features_count']} Features)")

threshold = st.sidebar.slider(
    "Detection Decision Threshold",
    min_value=0.1,
    max_value=0.9,
    value=0.5,
    step=0.05,
    help="Cutoff probability above which a flow is flagged as an attack.",
)

# Navigation
tabs = st.tabs([
    "📊 SOC Overview",
    "🔍 Flow Analyzer",
    "🚨 Alert Triage & Investigation",
    "📈 Model Evaluation & Transparency",
])

# -----------------------------------------------------------------------------
# TAB 1: SOC Overview
# -----------------------------------------------------------------------------
with tabs[0]:
    st.header("Security Operations Center (SOC) Overview")
    stats = repo.get_alert_statistics()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts Logged", stats["total_alerts"])
    col2.metric("New (Pending Triage)", stats["status_breakdown"]["New"])
    col3.metric("Under Investigation", stats["status_breakdown"]["Investigating"])
    col4.metric("High / Critical Priority", stats["high_priority_count"])

    st.subheader("Recent Alert Activity")
    recent_alerts = repo.list_alerts(limit=10)
    if recent_alerts:
        df_recent = pd.DataFrame([
            {
                "ID": a.finding_id[:8] + "...",
                "Timestamp": a.timestamp,
                "Label": a.label,
                "Confidence": f"{a.confidence:.1%}",
                "Severity": a.severity.value,
                "Status": a.status.value,
                "Proto": a.features_summary.get("proto", "-"),
                "Service": a.features_summary.get("service", "-"),
            }
            for a in recent_alerts
        ])
        st.dataframe(df_recent, use_container_width=True)
    else:
        st.info("No alerts logged yet. Use the Flow Analyzer tab to simulate or inspect traffic records.")

# -----------------------------------------------------------------------------
# TAB 2: Flow Analyzer
# -----------------------------------------------------------------------------
with tabs[1]:
    st.header("Real-Time Network Flow Analyzer")
    st.markdown("Inspect, score, and analyze individual network flow records through the detection pipeline.")

    # Quick test sample loader
    c1, c2, c3 = st.columns([1, 1, 2])
    load_attack = c1.button("📥 Load Sample Attack Flow")
    load_normal = c2.button("📥 Load Sample Normal Flow")

    default_flow = {
        "proto": "tcp",
        "service": "http",
        "state": "FIN",
        "dur": 0.05,
        "spkts": 4.0,
        "dpkts": 6.0,
        "sbytes": 540.0,
        "dbytes": 1280.0,
        "rate": 200.0,
        "sttl": 64.0,
        "dttl": 60.0,
        "sload": 86400.0,
        "dload": 204800.0,
        "sloss": 0.0,
        "dloss": 0.0,
        "sinpkt": 12.5,
        "dinpkt": 8.3,
        "sjit": 1.2,
        "djit": 0.8,
        "swin": 255.0,
        "stcpb": 1234567.0,
        "dtcpb": 7654321.0,
        "dwin": 255.0,
        "tcprtt": 0.015,
        "synack": 0.008,
        "ackdat": 0.007,
        "smean": 135.0,
        "dmean": 213.0,
        "trans_depth": 1.0,
        "response_body_len": 450.0,
        "ct_srv_src": 2.0,
        "ct_state_ttl": 0.0,
        "ct_dst_ltm": 1.0,
        "ct_src_dport_ltm": 1.0,
        "ct_dst_sport_ltm": 1.0,
        "ct_dst_src_ltm": 1.0,
        "is_ftp_login": 0.0,
        "ct_ftp_cmd": 0.0,
        "ct_flw_http_mthd": 1.0,
        "ct_src_ltm": 1.0,
        "ct_srv_dst": 2.0,
        "is_sm_ips_ports": 0.0,
    }

    if load_attack and TEST_DATA_PATH.exists():
        try:
            df_test = pd.read_csv(TEST_DATA_PATH)
            attack_sample = df_test[df_test["label"] == 1].iloc[0].to_dict()
            for k in default_flow:
                if k in attack_sample:
                    default_flow[k] = attack_sample[k]
            st.success("Loaded representative Attack flow from test dataset!")
        except Exception:
            pass
    elif load_normal and TEST_DATA_PATH.exists():
        try:
            df_test = pd.read_csv(TEST_DATA_PATH)
            normal_sample = df_test[df_test["label"] == 0].iloc[0].to_dict()
            for k in default_flow:
                if k in normal_sample:
                    default_flow[k] = normal_sample[k]
            st.info("Loaded representative Normal flow from test dataset!")
        except Exception:
            pass

    with st.form("flow_form"):
        st.subheader("Flow Attributes")
        fcol1, fcol2, fcol3 = st.columns(3)
        proto = fcol1.text_input("Protocol (proto)", value=str(default_flow["proto"]))
        service_input = fcol2.text_input("Service (service)", value=str(default_flow["service"]))
        state = fcol3.text_input("State (state)", value=str(default_flow["state"]))

        scol1, scol2, scol3, scol4 = st.columns(4)
        dur = scol1.number_input("Duration (dur)", value=float(default_flow["dur"]), format="%.4f")
        sbytes = scol2.number_input("Source Bytes (sbytes)", value=float(default_flow["sbytes"]), format="%.1f")
        dbytes = scol3.number_input("Dest Bytes (dbytes)", value=float(default_flow["dbytes"]), format="%.1f")
        rate = scol4.number_input("Packet Rate (rate)", value=float(default_flow["rate"]), format="%.2f")

        submitted = st.form_submit_button("🔍 Run Intrusion Detection")

    if submitted:
        input_payload = default_flow.copy()
        input_payload["proto"] = proto
        input_payload["service"] = service_input
        input_payload["state"] = state
        input_payload["dur"] = dur
        input_payload["sbytes"] = sbytes
        input_payload["dbytes"] = dbytes
        input_payload["rate"] = rate

        finding = service.detect_flow(input_payload, threshold=threshold)

        st.subheader("Detection Result")
        rcol1, rcol2, rcol3 = st.columns(3)

        if finding.is_alert:
            rcol1.error(f"🚨 **Verdict: {finding.label.upper()} DETECTED**")
        else:
            rcol1.success(f"✅ **Verdict: {finding.label.upper()} TRAFFIC**")

        rcol2.metric("Attack Probability", f"{finding.probability_attack:.1%}" if finding.probability_attack is not None else "N/A")
        rcol3.metric("Severity", finding.severity.value)

        # Evidence Breakdown
        st.json(finding.features_summary)

        if finding.is_alert:
            saved_alert = repo.save_finding_as_alert(finding)
            st.success(f"Alert automatically registered in repository with ID: `{saved_alert.finding_id}`")

# -----------------------------------------------------------------------------
# TAB 3: Alert Triage & Investigation
# -----------------------------------------------------------------------------
with tabs[2]:
    st.header("Security Alert Triage & Investigation Console")

    filt_col1, filt_col2, filt_col3 = st.columns([1, 1, 2])
    status_filter = filt_col1.selectbox("Filter Status", ["All", "New", "Investigating", "Resolved"])
    severity_filter = filt_col2.selectbox("Filter Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])

    query_status = None if status_filter == "All" else AlertStatus(status_filter)
    query_severity = None if severity_filter == "All" else AlertSeverity(severity_filter)

    alerts = repo.list_alerts(status=query_status, severity=query_severity, limit=200)

    if alerts:
        alert_options = {f"{a.finding_id[:8]} - {a.severity.value} - {a.timestamp} - {a.status.value}": a for a in alerts}
        selected_key = st.selectbox("Select Alert for Deep Investigation", list(alert_options.keys()))
        selected_alert = alert_options[selected_key]

        dcol1, dcol2 = st.columns([2, 1])
        with dcol1:
            st.subheader(f"Alert Investigation: `{selected_alert.finding_id}`")
            st.write(f"**Timestamp**: {selected_alert.timestamp}")
            st.write(f"**Classification**: {selected_alert.label} (Confidence: {selected_alert.confidence:.2%})")
            st.write(f"**Severity**: `{selected_alert.severity.value}`")
            st.write(f"**Model Used**: {selected_alert.model_name}")
            st.write("**Flow Evidence Indicators**:")
            st.json(selected_alert.features_summary)

        with dcol2:
            st.subheader("Analyst Triage Actions")
            new_status = st.selectbox(
                "Update Lifecycle Status",
                ["New", "Investigating", "Resolved"],
                index=["New", "Investigating", "Resolved"].index(selected_alert.status.value),
            )
            notes = st.text_area("Analyst Investigation Notes", value=selected_alert.analyst_notes or "")

            if st.button("💾 Save Triage Update"):
                repo.update_alert(
                    selected_alert.finding_id,
                    status=AlertStatus(new_status),
                    analyst_notes=notes,
                )
                st.success("Triage status and notes successfully updated!")
                st.rerun()

        st.divider()
        # Export CSV Button
        export_path = REPORTS_DIR / "exported_alerts.csv"
        repo.export_alerts_to_csv(export_path)
        with open(export_path, "rb") as f:
            st.download_button(
                label="📥 Export All Alerts as CSV",
                data=f,
                file_name="netsentinel_alerts.csv",
                mime="text/csv",
            )
    else:
        st.info("No alerts matching current filters.")

# -----------------------------------------------------------------------------
# TAB 4: Model Evaluation & Transparency
# -----------------------------------------------------------------------------
with tabs[3]:
    st.header("Baseline Model Evaluation & SOC Limitations")

    metrics_file = REPORTS_DIR / "evaluation" / "test_metrics.json"
    cm_image = REPORTS_DIR / "evaluation" / "confusion_matrices.png"

    if metrics_file.exists():
        with open(metrics_file, "r") as f:
            eval_data = json.load(f)

        m_col1, m_col2 = st.columns(2)
        lr = eval_data["logistic_regression"]
        dt = eval_data["decision_tree"]

        with m_col1:
            st.subheader("Logistic Regression (Linear)")
            st.metric("Test Accuracy", f"{lr['accuracy']:.2%}")
            st.metric("Recall (Detection Rate)", f"{lr['recall']:.2%}")
            st.metric("False Alarm Rate (FPR)", f"{lr['false_positive_rate']:.2%}")
            st.metric("ROC-AUC", f"{lr['roc_auc']:.4f}")

        with m_col2:
            st.subheader("Decision Tree (max_depth=10)")
            st.metric("Test Accuracy", f"{dt['accuracy']:.2%}")
            st.metric("Recall (Detection Rate)", f"{dt['recall']:.2%}")
            st.metric("False Alarm Rate (FPR)", f"{dt['false_positive_rate']:.2%}")
            st.metric("ROC-AUC", f"{dt['roc_auc']:.4f}")

    if cm_image.exists():
        st.subheader("Test Set Confusion Matrices (82,332 Evaluated Records)")
        st.image(str(cm_image), use_container_width=True)

    st.markdown(
        """
        ### 🔍 Critical Defense Engineering Analysis:
        * **High Recall (>98%)**: The Decision Tree baseline intercepts 98.3% of true attacks in the test set.
        * **False Positive Challenge (FPR ~32.7%)**: Despite high recall, approximately 32.7% of legitimate flows 
          trigger alerts. In production, this causes analyst fatigue and demonstrates why threshold tuning 
          and human triage workflows are essential.
        * **Offline Benchmark Limitations**: These metrics reflect synthetic testbed traffic (IXIA cyber range) 
          and must not be assumed to generalize across arbitrary enterprise networks without continuous retraining.
        """
    )
