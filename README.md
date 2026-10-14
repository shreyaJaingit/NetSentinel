# NetSentinel: Enterprise Network Intrusion Detection & Threat Intelligence Platform 🛡️

[![Platform](https://img.shields.io/badge/Platform-NetSentinel%20Enterprise-007acc.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.9%20%7C%203.11%2B-blue.svg)](#)
[![Inference](https://img.shields.io/badge/ONNX%20Runtime-Sub--5ms-green.svg)](#)
[![Explainability](https://img.shields.io/badge/SHAP-Real--Time-orange.svg)](#)
[![Streaming](https://img.shields.io/badge/Apache%20Kafka-7.5%2B-red.svg)](#)
[![Security](https://img.shields.io/badge/gVisor%20%2B%20mTLS-Hardened-blueviolet.svg)](#)

NetSentinel is a modular, enterprise-grade Network Intrusion Detection System (NIDS) and Threat Intelligence Platform. It combines asynchronous 5-tuple packet capture, 36-feature statistical flow aggregation aligned with the **UNSW-NB15** benchmark schema, **Apache Kafka** event streaming, **sub-5ms ONNX model inference**, real-time **TreeSHAP** root-cause attribution, automated **Snort 3 & Suricata** rule compilation, **gVisor-isolated firewall enforcement with mTLS webhooks**, and full observability via **Prometheus** and **Grafana**, alongside an analyst triage REST API and Streamlit SOC dashboard.

---

## Architecture Overview

```
                                      +-----------------------------+
                                      |   Raw Packets / Simulation  |
                                      +--------------+--------------+
                                                     |
                                                     v
                                      +-----------------------------+
                                      |   5-Tuple Flow Extractor    |
                                      |   UNSW-NB15 Feature Engine  |
                                      +--------------+--------------+
                                                     |
                                                     v
                                      +-----------------------------+
                                      |  Apache Kafka Telemetry Bus |
                                      | (linger_ms=10, acks=1, gzip)|
                                      +--------------+--------------+
                                                     |
                                                     v
                                      +-----------------------------+
                                      |   Kafka Consumer Service    |
                                      |   ONNX Runtime (< 0.2ms P99)|
                                      +--------------+--------------+
                                                     |
                                          (Anomaly Prob > 0.85)
                                                     v
                                      +-----------------------------+
                                      |   Real-Time SHAP Explainer  |
                                      |   Root-Cause Attribution    |
                                      +--------------+--------------+
                                                     |
                        +----------------------------+----------------------------+
                        |                                                         |
                        v                                                         v
         +------------------------------+                          +------------------------------+
         | Dynamic Rule Generator       |                          | Hardened Mitigation Engine   |
         | Snort 3 & Suricata Rules     |                          | gVisor Sandboxed nftables    |
         | Auto SID & Thresholding      |                          | Attested mTLS Webhook Post   |
         +------------------------------+                          +------------------------------+
                                                       |
                                                       v
                                        +------------------------------+
                                        | Prometheus /metrics (:8000)  |
                                        | Grafana Pre-Config Dashboards|
                                        +------------------------------+
```

---

## Directory Structure

```text
NetSentinel/
├── docker-compose.yml              # Zookeeper, Kafka, Prometheus, Grafana orchestration
├── requirements.txt                # Production, enterprise & benchmarking dependencies
├── README.md                       # Comprehensive system architecture & runbook
├── RESUME_METRICS.md               # Google XYZ executive resume metrics
├── config/
│   ├── config.yaml                 # Central enterprise configuration
│   ├── prometheus.yml              # Prometheus scrape targets
│   └── grafana/
│       ├── provisioning/           # Datasource and dashboard provisioning
│       └── dashboards/
│           └── netsentinel_dashboard.json # Grafana executive operational dashboard
├── src/
│   ├── sniffer/
│   │   ├── flow_extractor.py       # Async 5-tuple flow aggregation & Kafka streamer
│   │   └── ebpf_template.c         # XDP / eBPF kernel hook template
│   ├── inference/
│   │   ├── convert_model.py        # UNSW-NB15 multi-class classifier & ONNX export script
│   │   └── consumer.py             # Kafka consumer, ONNX session, TreeSHAP explainer
│   ├── mitigation/
│   │   ├── rule_generator.py       # Dynamic Snort 3 and Suricata rule compiler
│   │   └── block_engine.py         # gVisor firewall wrapper & mTLS webhook client
│   ├── monitoring/
│   │   └── metrics.py              # Prometheus metrics exporter (:8000/metrics)
│   ├── utils/
│   │   └── config.py               # Zero-dependency configuration loader
│   ├── alerts/                     # Persistent SQLite alert repository & schemas
│   ├── api/                        # FastAPI REST service & triage endpoints
│   ├── dashboard/                  # Streamlit SOC analyst investigation dashboard
│   └── detection/                  # Baseline detection models & preprocessors
├── scripts/
│   ├── generate_certs.py           # X.509 mTLS PKI generator (OpenSSL)
│   ├── run_pipeline.py             # End-to-end orchestrator and demonstrator
│   ├── build_preprocessor.py       # Preprocessor builder
│   ├── run_eda.py                  # Exploratory data analysis
│   └── train_baselines.py          # Baseline model trainer
├── gvisor/
│   └── runsc-spec.json             # gVisor OCI sandbox container specification
├── rules/
│   ├── netsentinel_snort3.rules    # Compiled dynamic Snort 3 signatures
│   └── netsentinel_suricata.rules  # Compiled dynamic Suricata signatures
├── certs/                          # Generated CA, Server, and Client X.509 certificates
└── tests/
    ├── test_pipeline.py            # Automated unit and integration test suite (Phase 1-4)
    ├── locustfile.py               # 5,000 req/sec Locust load testing benchmark
    ├── test_alerts.py              # Alert repository and status transitions
    └── test_api.py                 # FastAPI endpoint integration tests
```

---

## Quickstart Guide

### 1. Generate mTLS Certificates
```bash
python scripts/generate_certs.py
```
Generates Root CA (`ca.crt`, `ca.key`), Server Certificate with SAN (`server.crt`, `server.key`), and Client Certificate (`client.crt`, `client.key`) in `certs/`.

### 2. Compile ONNX Model
```bash
python src/inference/convert_model.py
```
Trains the ensemble model on UNSW-NB15 distributions and exports `models/unsw_nb15_model.onnx` and `models/unsw_nb15_model.json`.

### 3. Spin Up Infrastructure (Docker Compose)
```bash
docker compose up -d
```
Starts:
- **Zookeeper**: `localhost:2181`
- **Apache Kafka**: `localhost:9092` (auto-creates `network-telemetry` and `threat-alerts`)
- **Prometheus**: `http://localhost:9090`
- **Grafana**: `http://localhost:3000` (User: `admin` / Password: `admin`)

### 4. Run End-to-End Pipeline Demonstration
```bash
python scripts/run_pipeline.py --mode simulation --count 100 --delay-ms 5
```
Boots the metrics exporter on port 8000, initializes the mitigation engine, generates synthetic UNSW-NB15 flows, performs sub-5ms inference, generates Snort 3 / Suricata rules, enforces isolated firewall blocks, and logs telemetry.

### 5. Run 5,000 req/sec Load Benchmark
```bash
python tests/locustfile.py --target-rps 5000 --duration 5 --concurrency 16
```
Or with Locust CLI:
```bash
locust -f tests/locustfile.py --headless -u 500 -r 100 --run-time 15s
```

### 6. Run Automated Test Suite
```bash
python -m unittest tests/test_pipeline.py
```

---

## Observability & Dashboards

- **Prometheus Scrape Endpoint**: `http://localhost:8000/metrics`
- **Grafana Dashboard**: `http://localhost:3000` (pre-provisioned with `NetSentinel Enterprise Threat Intelligence Platform`)
  - Real-time panels: Packet Ingestion Rate, Active Concurrent Flows, Kafka Streaming Throughput, P50/P95/P99 Inference Latency Histograms, Threat Breakdown by Category, and Active Firewall Blocks.
- **Streamlit Analyst UI**: `streamlit run src/dashboard/app.py` for manual SOC alert investigation.
