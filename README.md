# NetSentinel 🛡️
### Network Intrusion Detection & Security Alert Investigation System

NetSentinel is an educational, defensive network security platform that combines machine learning intrusion detection with a structured Security Operations Center (SOC) investigation workflow.

---

## 🎯 Educational Goals
* **Network Security**: Understand network flows, protocol behaviors, and intrusion indicators.
* **Defensive Data Science**: Master data cleaning, feature engineering, and class imbalance handling without data leakage.
* **Machine Learning**: Train, evaluate, and interpret explainable baseline classifiers.
* **Security Operations**: Bridge the gap between ML inference and human security analyst triage through alerts and dashboard workflows.

---

## 🏗️ Architecture Overview
* **Ingestion & Preprocessing**: Safe CSV parsing, schema validation, and leakage-free transformations.
* **Detection Engine**: Scikit-learn classification pipeline with calibrated confidence scores.
* **Alert Management**: SQLite + SQLAlchemy repository tracking alert status (`New`, `Investigating`, `Resolved`) and analyst audit trails.
* **Backend REST API**: FastAPI application serving detection and investigation endpoints.
* **Analyst Dashboard**: Streamlit interface for incident triage, feature inspection, and metrics exploration.

---

## 🚀 Status
* Currently in **Phase 0: Environment & Project Setup**.
