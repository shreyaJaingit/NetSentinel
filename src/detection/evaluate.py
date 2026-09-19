"""
NetSentinel - Model Evaluation Module

Computes rigorous intrusion detection metrics:
- Accuracy, Precision, Recall, F1-Score, ROC-AUC
- Confusion Matrix (TP, TN, FP, FN)
- False Positive Rate (FPR) and False Negative Rate (FNR)
"""
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def evaluate_model(
    model: Any,
    X: np.ndarray,
    y: np.ndarray,
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """
    Evaluates a trained classifier on a dataset (typically the test set).
    
    Returns a comprehensive dictionary of security detection metrics.
    """
    # 1. Predictions and Probabilities
    has_proba = hasattr(model, "predict_proba")
    if has_proba:
        probabilities = model.predict_proba(X)[:, 1]
        y_pred = (probabilities >= threshold).astype(int)
        roc_auc = float(roc_auc_score(y, probabilities))
    else:
        y_pred = model.predict(X)
        probabilities = None
        roc_auc = None

    # 2. Basic Classification Metrics
    accuracy = float(accuracy_score(y, y_pred))
    precision = float(precision_score(y, y_pred, pos_label=1, zero_division=0))
    recall = float(recall_score(y, y_pred, pos_label=1, zero_division=0))
    f1 = float(f1_score(y, y_pred, pos_label=1, zero_division=0))

    # 3. Confusion Matrix Breakdown
    cm = confusion_matrix(y, y_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    # 4. Security-Specific Operational Rates
    # False Positive Rate (FPR) = FP / (FP + TN) -> rate of benign traffic falsely flagged as attacks
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    # False Negative Rate (FNR) = FN / (FN + TP) -> rate of attacks that slip past undetected (miss rate)
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "raw_matrix": [[tn, fp], [fn, tp]],
        },
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "total_samples": len(y),
        "threshold_used": threshold,
    }


def plot_side_by_side_confusion_matrices(
    results_lr: Dict[str, Any],
    results_dt: Dict[str, Any],
    output_path: Union[str, Path],
) -> None:
    """
    Renders clean side-by-side confusion matrix heatmaps for Logistic Regression
    and Decision Tree baselines.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    models_data = [
        ("Logistic Regression", results_lr, axes[0]),
        ("Decision Tree (max_depth=10)", results_dt, axes[1]),
    ]

    for title, res, ax in models_data:
        cm = np.array(res["confusion_matrix"]["raw_matrix"])
        im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        ax.set_title(f"{title}\nAccuracy: {res['accuracy']:.2%} | F1: {res['f1_score']:.4f}", fontsize=11)
        fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

        tick_marks = np.arange(2)
        ax.set_xticks(tick_marks)
        ax.set_xticklabels(["Normal (0)", "Attack (1)"], fontsize=10)
        ax.set_yticks(tick_marks)
        ax.set_yticklabels(["Normal (0)", "Attack (1)"], fontsize=10)

        # Annotate text counts
        thresh = cm.max() / 2.0
        for i in range(2):
            for j in range(2):
                val = cm[i, j]
                label = ""
                if i == 0 and j == 0:
                    label = f"TN\n{val:,}"
                elif i == 0 and j == 1:
                    label = f"FP\n{val:,}"
                elif i == 1 and j == 0:
                    label = f"FN\n{val:,}"
                elif i == 1 and j == 1:
                    label = f"TP\n{val:,}"
                
                ax.text(
                    j, i, label,
                    horizontalalignment="center",
                    verticalalignment="center",
                    color="white" if val > thresh else "black",
                    fontsize=10,
                    fontweight="bold"
                )

        ax.set_ylabel("True Ground Truth", fontsize=10)
        ax.set_xlabel("Model Predicted Label", fontsize=10)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
