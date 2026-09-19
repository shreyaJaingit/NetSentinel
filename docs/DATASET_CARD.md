# NetSentinel Dataset Card: UNSW-NB15

---

## 1. Dataset Overview & Source

* **Dataset Name**: UNSW-NB15 Network Intrusion Detection Dataset (Official Partitioned Subset)
* **Creators / Authors**: Dr. Nour Moustafa and Prof. Jill Slay
* **Institution**: Australian Centre for Cyber Security (ACCS), University of New South Wales (UNSW Canberra at the Australian Defence Force Academy)
* **Creation Year**: 2015
* **Official Website**: [UNSW Canberra Cyber Research Portal](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
* **Repository Mirror**: Hosted on Hugging Face / Figshare / Kaggle research repositories.

---

## 2. Academic Citation & Licensing

### Academic Citation
```bibtex
@inproceedings{moustafa2015unsw,
  title={UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)},
  author={Moustafa, Nour and Slay, Jill},
  booktitle={2015 Military Communications and Information Systems Conference (MilCIS)},
  pages={1--6},
  year={2015},
  organization={IEEE}
}
```

### Usage Terms & License
Free for academic, research, and non-commercial educational purposes, provided that appropriate citation and attribution are given to UNSW Canberra Cyber and the original authors.

---

## 3. Exact Files Used & Storage Layout

The offline files are stored locally under `data/` and excluded from version control:

| File Name | Role | Row Count | Column Count | File Size (Disk) | SHA256 Checksum |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`UNSW_NB15_training-set.csv`** | Model Training & Validation | `175,341` | `45` | `32,293,018` bytes (~30.8 MB) | `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa` |
| **`UNSW_NB15_testing-set.csv`** | Final Model Evaluation | `82,332` | `45` | `15,380,800` bytes (~14.7 MB) | `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559` |

---

## 4. Target Variables & Labels

The dataset provides two levels of ground truth:

### A. Binary Classification Target: `label`
* **`0`**: **Normal / Benign** network traffic.
* **`1`**: **Attack / Malicious** network traffic.

#### Class Proportions:
* **Training Set**:
  * Attack (`1`): `119,341` records (68.06%)
  * Normal (`0`): `56,000` records (31.94%)
* **Testing Set**:
  * Attack (`1`): `45,332` records (55.06%)
  * Normal (`0`): `37,000` records (44.94%)

### B. Multiclass Classification Target: `attack_cat`
The dataset categorizes attack traffic into 9 distinct modern threat families, plus `Normal`:

| Category | Description / Attack Manifestation | Count (Train) | Count (Test) |
| :--- | :--- | :--- | :--- |
| **Normal** | Everyday background user traffic (browsing, email, file transfers) | `56,000` | `37,000` |
| **Generic** | Cryptographic/hash collision attacks that work independently of target implementation | `40,000` | `18,871` |
| **Exploits** | Known vulnerability exploitation targeting OS, services, or web software | `33,393` | `11,132` |
| **Fuzzers** | Rapid transmission of random or malformed inputs to induce crashes | `18,184` | `6,062` |
| **DoS** | Denial-of-Service attacks overwhelming server buffers or network bandwidth | `12,264` | `4,089` |
| **Reconnaissance**| Probing network topology, active hosts, and open ports (e.g. port scans) | `10,491` | `3,496` |
| **Analysis** | Web-oriented attacks including directory traversal, spam, and HTML injection | `2,000` | `677` |
| **Backdoor** | Stealthy entry mechanism bypassing standard authentication mechanisms | `1,746` | `583` |
| **Shellcode** | Small snippets of executable code used as payload in software exploitation | `1,133` | `378` |
| **Worms** | Self-replicating autonomous payloads propagating across vulnerable hosts | `130` | `44` |

---

## 5. Security & Ethical Usage

* **Defensive Purpose**: Used solely to train and evaluate intrusion detection models and Security Operations Center (SOC) triage alerting.
* **Offline Only**: All analysis and training are conducted on offline, local CSV copies. No live network sniffing, promiscuous packet capture, or unauthorized scanning is performed.
* **Privacy Assurance**: Generated inside an isolated academic cyber range using the IXIA PerfectStorm tool. Contains no real personal identifiable information (PII), proprietary corporate data, or live credentials.

---

## 6. Known Limitations & Caveats

1. **Synthetic Testbed Artifacts**: Like all cyber-range benchmark datasets, the traffic was simulated in a laboratory testbed. Real-world corporate network traffic may exhibit different background distributions, seasonality, and novel zero-day behaviors.
2. **Class Imbalance in Attack Types**: High-frequency attacks (`Generic`, `Exploits`, `Fuzzers`) dominate, whereas stealthy or targeted attacks (`Worms`, `Shellcode`, `Backdoor`) constitute less than 2% of the dataset. Models evaluated on overall accuracy alone can mask complete failure to detect rare threats.
3. **Target Leakage Risk**: 
   * The column `id` is a sequential index and must **never** be used as a predictive feature.
   * When training a binary classifier, `attack_cat` must be excluded from feature inputs $X$ to prevent target leakage.
4. **Transport Integrity vs. Cryptographic Authenticity**:
   * SHA256 hashes confirm bitwise file integrity between local disk and repository host. However, because no author GPG key was published with the original 2015 CSV release, local hashes verify completeness rather than mathematical author non-repudiation.
