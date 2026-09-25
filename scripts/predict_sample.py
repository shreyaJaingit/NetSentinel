"""
NetSentinel - CLI Sample Prediction & Flow Triage Demonstration

Loads the trained model and preprocessor, runs inference on representative
samples from the test dataset, and prints structured security findings.
"""
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from src.config import TEST_DATA_PATH
from src.detection.service import DetectionService


def main():
    print("=" * 80)
    print("NetSentinel - CLI Detection & Security Alert Demonstration")
    print("=" * 80)

    service = DetectionService()
    info = service.get_service_info()
    print(f"[*] Loaded Model: {info['model_name']}")
    print(f"[*] Default Decision Threshold: {info['default_threshold']}")

    if not TEST_DATA_PATH.exists():
        print(f"[!] Test dataset not found at {TEST_DATA_PATH}. Exiting.")
        return

    print(f"[*] Reading sample records from {TEST_DATA_PATH.name}...")
    df_test = pd.read_csv(TEST_DATA_PATH)

    # Pick 3 attacks and 3 normal records
    attacks = df_test[df_test["label"] == 1].head(3)
    normals = df_test[df_test["label"] == 0].head(3)
    samples = pd.concat([normals, attacks]).reset_index(drop=True)

    print(f"[*] Analyzing {len(samples)} sample flows (3 Normal, 3 Attack)...\n")

    findings = service.detect_batch(samples)

    print("-" * 90)
    print(f"{'#':<3} | {'True Class':<10} | {'Predicted':<10} | {'Prob(Attack)':<13} | {'Confidence':<11} | {'Severity':<14} | {'Alert?'}")
    print("-" * 90)

    for i, finding in enumerate(findings):
        true_label = "Attack" if samples.iloc[i]["label"] == 1 else "Normal"
        true_cat = samples.iloc[i].get("attack_cat", "N/A")
        prob_str = f"{finding.probability_attack:.2%}" if finding.probability_attack is not None else "N/A"
        conf_str = f"{finding.confidence:.2%}"
        alert_str = "[ALERT]" if finding.is_alert else "[NORMAL]"

        print(
            f"{i+1:<3} | "
            f"{true_label:<10} | "
            f"{finding.label:<10} | "
            f"{prob_str:<13} | "
            f"{conf_str:<11} | "
            f"{finding.severity.value:<14} | "
            f"{alert_str}"
        )

    print("-" * 90)
    print("\n[OK] Demonstration complete. All findings structured per NetSentinel specifications.\n")


if __name__ == "__main__":
    main()
