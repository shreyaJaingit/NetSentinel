# NetSentinel 🛡️
### Network Intrusion Detection & Security Alert Investigation System

[![Tests](https://img.shields.io/badge/Tests-36%20Passed-brightgreen?style=flat-square)](file:///C:/Users/ASUS/projects/netsentinel/tests/)
[![Python](https://img.shields.io/badge/Python-3.9.6-blue?style=flat-square)](file:///C:/Users/ASUS/projects/netsentinel/)
[![Framework](https://img.shields.io/badge/FastAPI-0.115.6-009688?style=flat-square)](https://fastapi.tiangolo.com)
[![Dashboard](https://img.shields.io/badge/Streamlit-1.40.2-FF4B4B?style=flat-square)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-Educational%20Use-lightgrey?style=flat-square)](file:///C:/Users/ASUS/projects/netsentinel/LICENSE)

NetSentinel is a modular, defensive network intrusion detection and security alert triage platform. It combines machine learning classification over bidirectional network flow records with a structured Security Operations Center (SOC) investigation workflow, REST API, and analyst dashboard.

---

## 1. Project Overview

Modern network intrusion detection systems (NIDS) face a dual challenge: detecting high-velocity modern attacks while avoiding overwhelming security analysts with false alarms. NetSentinel implements an end-to-end defensive architecture:
1. Ingests and cleans multi-dimensional network flow telemetry.
2. Applies a leakage-free Scikit-Learn preprocessing pipeline (`ColumnTransformer`).
3. Classifies traffic into `Normal` or `Attack` using trained baseline classifiers.
4. Generates structured `SecurityFinding` objects with objective severity scoring (`INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
5. Persists alerts into an ACID SQLite repository.
6. Exposes a local FastAPI REST service and an interactive Streamlit investigation dashboard for human analyst triage.

---

## 2. Problem Statement

* **The Operational Problem**: Raw network packet streams generate millions of packets per second. Converting packets into flow records reduces volume, but static signature rules miss novel attacks, while complex "black box" deep learning models can be uninterpretable and brittle.
* **The Machine Learning Problem**: Network security datasets frequently suffer from:
  * Extreme feature dynamic ranges (e.g. byte counts spanning 0 to tens of millions).
  * Out-of-vocabulary categories (unseen TCP connection states in production).
  * Data leakage (target leakage from identifiers and ground-truth metadata).
  * High False Positive Rates (FPR), causing severe analyst alert fatigue.

NetSentinel addresses these challenges through rigorous, transparent software and ML engineering.

---

## 3. Architecture & End-to-End Workflow

```
[ Raw Network Flow Telemetry (CSV / JSON) ]
                      │
                      ▼
[ Validation & Contract Enforcement ]
  • Requires 42 input features (39 numerical, 3 categorical)
  • Explicitly drops 'id' and isolates 'attack_cat' (Leakage Elimination)
                      │
                      ▼
[ Data Preprocessing Pipeline ]
  • service = '-' remapped to 'none' (preserves non-L7 traffic context)
  • Categoricals ('proto', 'service', 'state') -> OneHotEncoder(handle_unknown='ignore')
  • Numericals -> StandardScaler() (fit strictly on training data)
                      │
                      ▼
[ Baseline ML Classifiers ]
  • Decision Tree (depth=10, min_samples_leaf=10) [Default Baseline]
  • Logistic Regression (lbfgs, C=1.0)
                      │
                      ▼
[ Structured Security Finding ]
  • Binary label ('Normal' vs 'Attack')
  • Confidence score & estimated probability
  • Objectively derived severity (CRITICAL, HIGH, MEDIUM, LOW)
  • Extracted flow evidence metrics (protocol, duration, byte counts)
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
[ SQLite Alert Repository ]   [ FastAPI REST API ]
  • Tracks lifecycle state      • POST /predict
    ('New', 'Investigating',    • POST /predict/batch
     'Resolved')                • GET /alerts & /alerts/stats
  • Analyst investigation       • GET /alerts/export/csv
    notes & audit trail         • Interactive Swagger Docs
        │
        ▼
[ Streamlit Analyst Dashboard ]
  • SOC overview KPI metrics
  • Real-time flow analyzer & simulator
  • Triage console with status transitions & notes
  • Model evaluation & confusion matrix review
```

---

## 4. Dataset

NetSentinel uses the benchmark **UNSW-NB15** dataset, created by the Australian Centre for Cyber Security (ACCS) at UNSW Canberra:
* **Training Set**: `UNSW_NB15_training-set.csv` (175,341 records: 68.06% Attack, 31.94% Normal).
* **Testing Set**: `UNSW_NB15_testing-set.csv` (82,332 records: 55.06% Attack, 44.94% Normal).
* **Attack Families Represented (9 Categories)**: `Generic`, `Exploits`, `Fuzzers`, `DoS`, `Reconnaissance`, `Analysis`, `Backdoor`, `Shellcode`, `Worms`.
* **Details**: Full documentation, column descriptions, and citations are documented in [`docs/DATASET_CARD.md`](docs/DATASET_CARD.md).

---

## 5. Preprocessing Pipeline

Implemented in [`src/data/preprocessing.py`](src/data/preprocessing.py):
* **Leakage Safeguards**: `id` is systematically removed to prevent memorization of row ordering. `attack_cat` is excluded from feature inputs $X$.
* **Application Service Mapping (`service = '-'`)**: A hyphen indicates no layer-7 application was identified. Rather than treating it as missing data, it is cleanly mapped to `'none'`.
* **Out-of-Vocabulary (OOV) Protection**: The test set contains connection states (`ACC`, `CLO`) absent from the training set. Setting `handle_unknown='ignore'` in `OneHotEncoder` causes unseen categories to encode as zero vectors, preventing runtime crashes.
* **Fit Integrity**: Scaling ($\mu, \sigma$) and one-hot vocabularies are fit **strictly** on the training dataset.

---

## 6. Machine Learning Models

Trained in [`src/detection/train.py`](src/detection/train.py) and evaluated in [`src/detection/evaluate.py`](src/detection/evaluate.py):
1. **Decision Tree Classifier (Primary Baseline)**:
   * Constrained to `max_depth=10`, `min_samples_split=20`, `min_samples_leaf=10`, `random_state=42`.
   * Fast, interpretable, non-linear feature partitioning.
2. **Logistic Regression (Comparative Linear Baseline)**:
   * `C=1.0`, `solver='lbfgs'`, `max_iter=1000`, `random_state=42`.
   * Evaluates linear separability of normalized network flows.

Artifacts are persisted in [`models/`](models/):
* `models/preprocessor.joblib` (10 KB)
* `models/baseline_decision_tree.joblib` (32.5 KB)
* `models/baseline_logistic_regression.joblib` (2.9 KB)
* `models/baseline_model.joblib` (Default active model)

---

## 7. Model Evaluation & Performance

Evaluated on the held-out test partition (**82,332 unseen flow records**):

| Metric | Logistic Regression | Decision Tree (`depth=10`) |
| :--- | :--- | :--- |
| **Accuracy** | 80.95% | **84.38%** |
| **Precision (Attack)** | 75.36% | **78.65%** |
| **Recall (Detection Rate)** | 97.18% | **98.33%** |
| **F1-Score** | 0.8489 | **0.8740** |
| **ROC-AUC** | 0.9555 | **0.9732** |
| **False Positive Rate (FPR)** | 38.93% | **32.71%** |
| **False Negative Rate (FNR)** | 2.82% | **1.67%** |

### Test Confusion Matrix Breakdown:
```
Decision Tree (82,332 flows):
                  Predicted Normal    Predicted Attack
Actual Normal        24,899 (TN)        12,101 (FP)
Actual Attack           757 (FN)        44,575 (TP)
```
* **Detection Strength**: Extremely low miss rate (only 757 out of 45,332 attacks missed; 98.33% recall).
* **Operational Trade-off**: 12,101 false positives on normal traffic (32.71% FPR). This reflects the reality of IDS baselines and justifies the triage console and threshold controls.

---

## 8. Detection & Alert Structure

Every inference produces a strongly-typed `SecurityFinding`:
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
    "sbytes": 540.0,
    "dbytes": 1280.0
  }
}
```

Severity is assigned objectively:
* `prob_attack >= 0.90` $\rightarrow$ **CRITICAL**
* `prob_attack >= 0.75` $\rightarrow$ **HIGH**
* `prob_attack >= 0.60` $\rightarrow$ **MEDIUM**
* `prob_attack < 0.60` $\rightarrow$ **LOW**
* Normal flow $\rightarrow$ **INFORMATIONAL**

---

## 9. Installation & Setup

### Prerequisites
* Windows, Linux, or macOS
* Python 3.9+ installed
* Git

### Step-by-Step Setup
1. **Clone the repository**:
   ```bash
   git clone https://github.com/shreyaJaingit/netsentinel.git
   cd netsentinel
   ```
2. **Create and activate the virtual environment**:
   ```powershell
   # Windows PowerShell
   py -3.9 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   ```bash
   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 10. How to Run

### A. Run CLI Sample Demonstration
Run inference on representative test records directly in the terminal:
```bash
python scripts/predict_sample.py
```

### B. Launch the FastAPI REST Backend
Start the local REST API server:
```bash
uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```
* Interactive Swagger Docs: `http://127.0.0.1:8000/docs`

### C. Launch the Security Analyst Dashboard
In a separate terminal:
```bash
streamlit run src/dashboard/app.py
```
* Dashboard URL: `http://localhost:8501`

---

## 11. Automated Testing

NetSentinel includes an extensive automated test suite covering sanity, data preprocessing, model inference, alert management, and REST endpoints:

```bash
pytest -v
```

**Actual Test Result**:
```text
======================= 36 passed, 14 warnings in 9.54s =======================
```
* 100% test pass rate across 36 test cases.

---

## 12. Project Structure

```text
netsentinel/
├── README.md                      # Comprehensive project documentation
├── requirements.txt               # Pinned, tested dependencies
├── .gitignore                     # Defensive exclusions (models, datasets, venv, caches)
├── .env.example                   # Local configuration template
├── data/
│   ├── README.md                  # Data safety policies
│   ├── UNSW_NB15_training-set.csv # Offline training partition (ignored by git)
│   └── UNSW_NB15_testing-set.csv  # Offline testing partition (ignored by git)
├── docs/
│   ├── DATASET_CARD.md            # Dataset provenance, schema, and ethical notes
│   ├── MODEL_CARD.md              # Model card, evaluation metrics, and trade-offs
│   └── API_USAGE.md               # REST API endpoints, examples, and curl commands
├── models/
│   ├── README.md                  # Serialization policy
│   ├── preprocessor.joblib        # Fitted ColumnTransformer bundle (ignored by git)
│   ├── baseline_decision_tree.joblib (ignored by git)
│   ├── baseline_logistic_regression.joblib (ignored by git)
│   └── baseline_model.joblib      # Active default baseline (ignored by git)
├── reports/
│   ├── eda/                       # Generated EDA charts and summary JSON
│   └── evaluation/                # Confusion matrix plots and test_metrics.json
├── scripts/
│   ├── run_eda.py                 # Dynamic dataset exploration script
│   ├── build_preprocessor.py      # Preprocessing pipeline builder
│   ├── train_baselines.py         # Model training and evaluation runner
│   └── predict_sample.py          # Quick CLI sample prediction demonstration
├── src/
│   ├── __init__.py
│   ├── config.py                  # Global contracts, paths, and feature schemas
│   ├── alerts/
│   │   ├── __init__.py
│   │   ├── schemas.py             # Pydantic schemas for flows, findings, and alerts
│   │   └── repository.py          # SQLite & SQLAlchemy alert persistence and triage
│   ├── api/
│   │   ├── __init__.py
│   │   └── main.py                # FastAPI application with REST endpoints
│   ├── dashboard/
│   │   ├── __init__.py
│   │   └── app.py                 # Streamlit security analyst triage dashboard
│   ├── data/
│   │   ├── __init__.py
│   │   └── preprocessing.py       # Cleaning, leakage prevention, ColumnTransformer
│   └── detection/
│       ├── __init__.py
│       ├── train.py               # Model fitting routines and bundle saving
│       ├── evaluate.py            # Classification metrics and confusion matrix plotting
│       ├── predict.py             # Single and batch prediction utilities
│       └── service.py             # DetectionService orchestration layer
└── tests/
    ├── __init__.py
    ├── test_sanity.py             # Python runtime and package import checks
    ├── test_preprocessing.py      # Leakage, scaling, and OOV category handling
    ├── test_detection.py          # Model training, evaluation, and serialization
    ├── test_detection_service.py  # DetectionService inference and threshold checks
    ├── test_alerts.py             # SQLite alert CRUD, status transitions, and CSV export
    └── test_api.py                # FastAPI REST endpoint integration tests
```

---

## 13. Limitations

* **False Alarm Volume (FPR ~32.7%)**: The baseline Decision Tree flags ~32.7% of benign flows as attacks. In live operations, this requires confidence threshold tuning (e.g. threshold > 0.75) and human analyst oversight.
* **Testbed Environment**: Trained on simulated traffic from the IXIA cyber range. Real-world corporate networks contain different protocols and traffic volumes.
* **Offline Only**: Operates on structured flow records; does not capture live promiscuous network packets or automatically block IP addresses.
* **Uncalibrated Probabilities**: Model prediction probabilities are uncalibrated leaf distributions, serving as ranking heuristics rather than Bayesian certainties.

---

## 14. Future Improvements (Roadmap)

* [ ] **Ensemble Models**: Train Random Forest and XGBoost classifiers to reduce false alarms.
* [ ] **Probability Calibration**: Apply Isotonic Regression or Platt Scaling to improve probability reliability.
* [ ] **Multiclass Classification**: Implement secondary classifier to predict specific attack categories (`DoS`, `Exploits`, `Fuzzers`).
* [ ] **Live Suricata / Zeek Ingestion**: Connect to live Zeek JSON log outputs for continuous flow monitoring.
* [ ] **Automated Retraining**: Implement drift detection (Evidently AI / Population Stability Index) to trigger automated retraining when traffic distributions shift.
