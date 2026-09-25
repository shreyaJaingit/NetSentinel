# NetSentinel API & Service Usage Guide

The NetSentinel REST API provides local, offline endpoints for flow inference, batch scoring, and Security Operations Center (SOC) alert triage.

---

## 1. Starting the Services

### Activate the Virtual Environment
**Windows PowerShell**:
```powershell
cd C:\Users\ASUS\projects\netsentinel
.\.venv\Scripts\Activate.ps1
```

### Start the REST API
```powershell
uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```
* **API Base URL**: `http://127.0.0.1:8000`
* **Interactive Swagger UI**: `http://127.0.0.1:8000/docs`
* **Alternative ReDoc UI**: `http://127.0.0.1:8000/redoc`

### Start the Security Analyst Dashboard (Streamlit)
In a separate terminal window:
```powershell
streamlit run src/dashboard/app.py
```
* **Dashboard URL**: `http://localhost:8501`

---

## 2. API Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | API status and links to documentation |
| `GET` | `/health` | Health check reporting model and preprocessor status |
| `GET` | `/model/info` | Active model architecture, feature contract, and metadata |
| `POST` | `/predict` | Real-time classification of a single network flow |
| `POST` | `/predict/batch` | High-throughput classification of a batch of flow records |
| `GET` | `/alerts` | Query recorded alerts with status and severity filters |
| `GET` | `/alerts/stats` | Aggregated alert metrics (New, Investigating, Resolved) |
| `GET` | `/alerts/{alert_id}` | Retrieve deep inspection details for a specific alert |
| `PATCH`| `/alerts/{alert_id}` | Update alert lifecycle status and append analyst notes |
| `GET` | `/alerts/export/csv` | Download full CSV report of recorded alerts |

---

## 3. Example Request & Response

### Real-Time Flow Inference (`POST /predict`)

#### Example Request (`curl`):
```bash
curl -X POST "http://127.0.0.1:8000/predict?save_alert=true&threshold=0.5" \
     -H "Content-Type: application/json" \
     -d '{
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
       "is_sm_ips_ports": 0.0
     }'
```

#### Example Response (`200 OK`):
```json
{
  "finding_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "timestamp": "2026-09-25T15:45:00.123456+00:00",
  "prediction": 1,
  "label": "Attack",
  "probability_attack": 0.8852,
  "confidence": 0.8852,
  "is_alert": true,
  "severity": "HIGH",
  "model_name": "DecisionTreeClassifier",
  "threshold_used": 0.5,
  "features_summary": {
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
    "dttl": 60.0
  }
}
```

---

## 4. Triage Workflow Update (`PATCH /alerts/{alert_id}`)

#### Example Request:
```bash
curl -X PATCH "http://127.0.0.1:8000/alerts/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d" \
     -H "Content-Type: application/json" \
     -d '{
       "status": "Investigating",
       "analyst_notes": "Correlated with egress volume surge. IP quarantined locally for review."
     }'
```

#### Example Response:
```json
{
  "finding_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "status": "Investigating",
  "analyst_notes": "Correlated with egress volume surge. IP quarantined locally for review.",
  "updated_at": "2026-09-25T15:50:12.654321+00:00"
}
```
