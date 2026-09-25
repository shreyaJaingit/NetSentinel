# NetSentinel Model Card: Baseline Intrusion Detection Models

---

## 1. Model Overview

* **Model Name**: NetSentinel Baseline Classifiers (Decision Tree & Logistic Regression)
* **Model Versions**: `1.0.0`
* **Task**: Binary Network Flow Classification (`0`: Normal / Benign, `1`: Malicious / Attack)
* **Underlying Algorithms**:
  * **Primary Baseline**: Scikit-Learn `DecisionTreeClassifier` (`max_depth=10`, `min_samples_split=20`, `min_samples_leaf=10`, `random_state=42`)
  * **Comparative Baseline**: Scikit-Learn `LogisticRegression` (`C=1.0`, `max_iter=1000`, `solver='lbfgs'`, `random_state=42`)
* **Input Features**: 42 raw network flow telemetry attributes (3 categorical + 39 continuous numeric metrics).
* **Transformed Features**: 194 numeric features post-standard scaling and one-hot encoding.
* **Artifact Files**:
  * `models/preprocessor.joblib` (10.0 KB)
  * `models/baseline_decision_tree.joblib` (32.5 KB)
  * `models/baseline_logistic_regression.joblib` (2.9 KB)
  * `models/baseline_model.joblib` (Default baseline)

---

## 2. Intended Use & Target Users

* **Intended Use**: Educational and defensive intrusion detection prototyping. Designed to demonstrate data preprocessing, leakage-free pipeline engineering, baseline classification, and Security Operations Center (SOC) alert triage.
* **Primary Users**: Security analysts, cybersecurity students, and detection engineers.
* **Out-of-Scope / Non-Goals**:
  * NOT an active intrusion prevention system (IPS); does not automatically drop packets or block IP addresses.
  * NOT intended for live packet capture on unauthorized third-party networks.
  * NOT a guarantee of detection against zero-day exploits or evasive adversary tradecraft.

---

## 3. Training & Evaluation Methodology

* **Dataset**: UNSW-NB15 official partitioned benchmark.
* **Training Set**: `175,341` records (68.06% Attack, 31.94% Normal).
* **Test Set**: `82,332` records (55.06% Attack, 44.94% Normal).
* **Leakage Safeguards**:
  * `id` strictly dropped to avoid sequence memorization.
  * `attack_cat` strictly excluded from feature inputs $X$ to eliminate target leakage.
  * Preprocessing scaling parameters ($\mu, \sigma$) and one-hot categories fit **only** on training data.
  * Out-of-vocabulary test categories (`ACC`, `CLO` in `state`) handled defensively via `handle_unknown='ignore'`.

---

## 4. Performance & Evaluation Metrics

Evaluated on the held-out test set (`82,332` records):

| Metric | Logistic Regression | Decision Tree (`depth=10`) |
| :--- | :--- | :--- |
| **Accuracy** | 80.95% | **84.38%** |
| **Precision (Attack)** | 75.36% | **78.65%** |
| **Recall (Detection Rate)** | 97.18% | **98.33%** |
| **F1-Score** | 0.8489 | **0.8740** |
| **ROC-AUC** | 0.9555 | **0.9732** |
| **False Positive Rate (FPR)** | 38.93% | **32.71%** |
| **False Negative Rate (FNR)** | 2.82% | **1.67%** |

### Confusion Matrix Breakdown:

```
Decision Tree (max_depth=10):
                  Predicted Normal    Predicted Attack
Actual Normal        24,899 (TN)        12,101 (FP)
Actual Attack           757 (FN)        44,575 (TP)

Logistic Regression:
                  Predicted Normal    Predicted Attack
Actual Normal        22,597 (TN)        14,403 (FP)
Actual Attack         1,278 (FN)        44,054 (TP)
```

---

## 5. Security & Operational Trade-offs

1. **High Recall (Detection Rate = 98.33%)**:
   * *Strength*: The Decision Tree successfully flagged 44,575 out of 45,332 attacks, missing only 757 attacks (1.67% False Negative Rate). In defensive security, missing an attack is hazardous because a missed threat can lead to network compromise.
2. **High False Positive Rate (FPR = 32.71%)**:
   * *Limitation*: Out of 37,000 legitimate background flows, 12,101 were falsely flagged as attacks.
   * *SOC Impact*: In an operational security environment, this false alarm volume causes **alert fatigue**. Analysts spend considerable time triaging false alerts.
   * *Mitigation*: NetSentinel assigns severity levels based on model confidence and provides an interactive triage console to allow analysts to filter by threshold, review evidence, and document status.

---

## 6. Model Limitations & Ethical Considerations

* **Cyber-Range Testbed Bias**: The models were trained on simulated laboratory flows (IXIA PerfectStorm) and may not generalize directly to diverse live enterprise networks without domain adaptation.
* **Concept Drift**: Attack patterns evolve rapidly. Static models must be periodically retrained and monitored for data drift.
* **Uncalibrated Probabilities**: Raw output probabilities from tree leaves and logistic sigmoid functions are useful heuristics for prioritization, but do not represent true Bayesian posterior probabilities.
