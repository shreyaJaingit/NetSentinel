"""
NetSentinel Phase 3 - Baseline Model Training and Evaluation Script

Trains Logistic Regression and Decision Tree baselines on UNSW-NB15,
evaluates both on the official test set, saves serialized model artifacts to models/,
and saves evaluation reports and confusion matrices to reports/evaluation/.
"""
import json
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd

from src.config import (
    MODEL_PATH,
    MODELS_DIR,
    PREPROCESSOR_PATH,
    REPORTS_DIR,
    TEST_DATA_PATH,
    TRAIN_DATA_PATH,
)
from src.data.preprocessing import (
    load_preprocessor_bundle,
    prepare_features_and_labels,
)
from src.detection.evaluate import (
    evaluate_model,
    plot_side_by_side_confusion_matrices,
)
from src.detection.train import (
    save_model_bundle,
    train_decision_tree,
    train_logistic_regression,
)

EVAL_DIR = REPORTS_DIR / "evaluation"
EVAL_DIR.mkdir(parents=True, exist_ok=True)


def main():
    print("=" * 80)
    print("NetSentinel Phase 3: Baseline Intrusion Detection Model Training & Evaluation")
    print("=" * 80)

    # 1. Load Preprocessor
    print(f"\n[1] Loading fitted preprocessor bundle from {PREPROCESSOR_PATH}...")
    prep_bundle = load_preprocessor_bundle(PREPROCESSOR_PATH)
    preprocessor = prep_bundle["preprocessor"]
    print(f"    Loaded preprocessor fitted on {prep_bundle['metadata'].get('train_samples_fitted', 'N/A')} samples.")

    # 2. Load Raw Datasets
    print(f"\n[2] Loading raw datasets...")
    df_train = pd.read_csv(TRAIN_DATA_PATH)
    df_test = pd.read_csv(TEST_DATA_PATH)
    print(f"    Train records: {len(df_train):,}")
    print(f"    Test records:  {len(df_test):,}")

    # 3. Prepare Features and Targets (Strict Leakage Prevention)
    print(f"\n[3] Extracting features and targets (strictly dropping 'id' and 'attack_cat')...")
    X_train_raw, y_train, _ = prepare_features_and_labels(df_train, is_training=True)
    X_test_raw, y_test, _ = prepare_features_and_labels(df_test, is_training=False)

    assert "id" not in X_train_raw.columns, "Leakage: 'id' present in X_train!"
    assert "attack_cat" not in X_train_raw.columns, "Leakage: 'attack_cat' present in X_train!"
    assert "label" not in X_train_raw.columns, "Leakage: 'label' present in X_train!"

    # 4. Transform Feature Matrices
    print(f"\n[4] Transforming feature matrices using fitted preprocessor...")
    X_train = preprocessor.transform(X_train_raw)
    X_test = preprocessor.transform(X_test_raw)
    print(f"    X_train shape: {X_train.shape}")
    print(f"    X_test shape:  {X_test.shape}")

    # 5. Train Model 1: Logistic Regression
    print(f"\n[5] Training Model 1: Logistic Regression (C=1.0, max_iter=1000, seed=42)...")
    lr_model = train_logistic_regression(
        X_train=X_train,
        y_train=y_train.values,
        random_state=42,
        max_iter=1000,
        C=1.0,
    )
    print("    [OK] Logistic Regression training complete.")

    # 6. Train Model 2: Decision Tree
    print(f"\n[6] Training Model 2: Decision Tree (max_depth=10, min_samples_leaf=10, seed=42)...")
    dt_model = train_decision_tree(
        X_train=X_train,
        y_train=y_train.values,
        random_state=42,
        max_depth=10,
        min_samples_split=20,
        min_samples_leaf=10,
    )
    print("    [OK] Decision Tree training complete.")

    # 7. Evaluate on the Unseen Test Set
    print(f"\n[7] Evaluating both models on the test set (82,332 records)...")
    res_lr = evaluate_model(lr_model, X_test, y_test.values)
    res_dt = evaluate_model(dt_model, X_test, y_test.values)

    # Print Comparison Table
    print("\n" + "-" * 75)
    print(f"{'Metric':<25} | {'Logistic Regression':<22} | {'Decision Tree (depth=10)':<22}")
    print("-" * 75)
    print(f"{'Accuracy':<25} | {res_lr['accuracy']:<22.4%} | {res_dt['accuracy']:<22.4%}")
    print(f"{'Precision (Attack)':<25} | {res_lr['precision']:<22.4%} | {res_dt['precision']:<22.4%}")
    print(f"{'Recall (Attack)':<25} | {res_lr['recall']:<22.4%} | {res_dt['recall']:<22.4%}")
    print(f"{'F1-Score':<25} | {res_lr['f1_score']:<22.4f} | {res_dt['f1_score']:<22.4f}")
    print(f"{'ROC-AUC':<25} | {res_lr['roc_auc']:<22.4f} | {res_dt['roc_auc']:<22.4f}")
    print(f"{'False Positive Rate':<25} | {res_lr['false_positive_rate']:<22.4%} | {res_dt['false_positive_rate']:<22.4%}")
    print(f"{'False Negative Rate':<25} | {res_lr['false_negative_rate']:<22.4%} | {res_dt['false_negative_rate']:<22.4%}")
    print("-" * 75)
    print(f"{'True Positives (TP)':<25} | {res_lr['confusion_matrix']['true_positives']:<22,d} | {res_dt['confusion_matrix']['true_positives']:<22,d}")
    print(f"{'True Negatives (TN)':<25} | {res_lr['confusion_matrix']['true_negatives']:<22,d} | {res_dt['confusion_matrix']['true_negatives']:<22,d}")
    print(f"{'False Positives (FP)':<25} | {res_lr['confusion_matrix']['false_positives']:<22,d} | {res_dt['confusion_matrix']['false_positives']:<22,d}")
    print(f"{'False Negatives (FN)':<25} | {res_lr['confusion_matrix']['false_negatives']:<22,d} | {res_dt['confusion_matrix']['false_negatives']:<22,d}")
    print("-" * 75)

    # 8. Save Serialized Models
    print(f"\n[8] Saving serialized model artifacts to {MODELS_DIR}...")
    lr_path = MODELS_DIR / "baseline_logistic_regression.joblib"
    dt_path = MODELS_DIR / "baseline_decision_tree.joblib"

    save_model_bundle(
        model=lr_model,
        output_path=lr_path,
        model_name="LogisticRegression",
        metadata={
            "algorithm": "LogisticRegression",
            "hyperparameters": {"C": 1.0, "max_iter": 1000, "solver": "lbfgs", "random_state": 42},
            "test_metrics": res_lr,
        },
    )
    print(f"    [OK] Saved {lr_path.name}")

    save_model_bundle(
        model=dt_model,
        output_path=dt_path,
        model_name="DecisionTreeClassifier",
        metadata={
            "algorithm": "DecisionTreeClassifier",
            "hyperparameters": {"max_depth": 10, "min_samples_split": 20, "min_samples_leaf": 10, "random_state": 42},
            "test_metrics": res_dt,
        },
    )
    print(f"    [OK] Saved {dt_path.name}")

    # Set the champion baseline model as default MODEL_PATH (models/baseline_model.joblib)
    champion_model = dt_model if res_dt["f1_score"] >= res_lr["f1_score"] else lr_model
    champion_name = "DecisionTreeClassifier" if res_dt["f1_score"] >= res_lr["f1_score"] else "LogisticRegression"
    champion_metrics = res_dt if res_dt["f1_score"] >= res_lr["f1_score"] else res_lr

    save_model_bundle(
        model=champion_model,
        output_path=MODEL_PATH,
        model_name=champion_name,
        metadata={
            "algorithm": champion_name,
            "is_default_baseline": True,
            "test_metrics": champion_metrics,
        },
    )
    print(f"    [OK] Designated {champion_name} as default baseline -> saved {MODEL_PATH.name}")

    # 9. Save Evaluation Reports and Visualizations
    print(f"\n[9] Saving evaluation reports and visualizations to {EVAL_DIR}...")
    metrics_json_path = EVAL_DIR / "test_metrics.json"
    with open(metrics_json_path, "w") as f:
        json.dump({
            "logistic_regression": res_lr,
            "decision_tree": res_dt,
            "dataset_info": {
                "train_samples": len(df_train),
                "test_samples": len(df_test),
                "test_attack_count": int((y_test == 1).sum()),
                "test_normal_count": int((y_test == 0).sum()),
            }
        }, f, indent=2)
    print(f"    [OK] Saved JSON metrics: {metrics_json_path.name}")

    cm_plot_path = EVAL_DIR / "confusion_matrices.png"
    plot_side_by_side_confusion_matrices(res_lr, res_dt, cm_plot_path)
    print(f"    [OK] Saved confusion matrix plot: {cm_plot_path.name}")

    print("\n" + "=" * 80)
    print("Phase 3 Model Training & Evaluation Complete.")
    print("=" * 80)


if __name__ == "__main__":
    main()
