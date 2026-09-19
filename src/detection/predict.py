"""
NetSentinel - Inference & Detection Module

Provides clean, validated inference functions for single flow records
and batch DataFrames using the trained model and serialized preprocessor.
"""
from typing import Any, Dict, Optional, Union

import numpy as np
import pandas as pd

from src.config import EXPECTED_RAW_FEATURES
from src.data.preprocessing import clean_raw_dataframe


def predict_single_flow(
    model: Any,
    preprocessor: Any,
    raw_flow: Dict[str, Any],
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """
    Performs intrusion detection inference on a single raw flow record (dict).
    
    Parameters:
    - model: Trained classifier.
    - preprocessor: Fitted Scikit-learn ColumnTransformer.
    - raw_flow: Dictionary containing the raw flow attributes.
    - threshold: Probability cutoff for flagging an attack.
    
    Returns:
    - Dictionary with predicted class, probabilities, confidence, and alert flag.
    """
    # 1. Contract Validation: Ensure required features are present
    missing = [feat for feat in EXPECTED_RAW_FEATURES if feat not in raw_flow]
    if missing:
        raise ValueError(f"Input flow record is missing required features: {missing}")

    # 2. Build single-row DataFrame in deterministic feature order
    df_raw = pd.DataFrame([{feat: raw_flow[feat] for feat in EXPECTED_RAW_FEATURES}])

    # 3. Clean and Transform
    df_clean = clean_raw_dataframe(df_raw)
    X_trans = preprocessor.transform(df_clean[EXPECTED_RAW_FEATURES])

    # 4. Predict Class and Probabilities
    has_proba = hasattr(model, "predict_proba")
    if has_proba:
        probs = model.predict_proba(X_trans)[0]
        prob_normal = float(probs[0])
        prob_attack = float(probs[1])
        predicted_label = int(prob_attack >= threshold)
        confidence = prob_attack if predicted_label == 1 else prob_normal
    else:
        predicted_label = int(model.predict(X_trans)[0])
        prob_attack = 1.0 if predicted_label == 1 else 0.0
        prob_normal = 1.0 - prob_attack
        confidence = 1.0

    return {
        "predicted_label": predicted_label,
        "predicted_class": "Attack" if predicted_label == 1 else "Normal",
        "confidence": round(confidence, 4),
        "probability_attack": round(prob_attack, 4),
        "probability_normal": round(prob_normal, 4),
        "is_alert": bool(predicted_label == 1),
        "threshold_used": threshold,
    }


def predict_batch(
    model: Any,
    preprocessor: Any,
    df_raw: pd.DataFrame,
    threshold: float = 0.5,
) -> pd.DataFrame:
    """
    Performs inference on a batch of raw flow records.
    Returns a DataFrame containing predictions and alert flags.
    """
    # Check required features
    missing = [feat for feat in EXPECTED_RAW_FEATURES if feat not in df_raw.columns]
    if missing:
        raise ValueError(f"Batch DataFrame missing required features: {missing}")

    df_clean = clean_raw_dataframe(df_raw[EXPECTED_RAW_FEATURES])
    X_trans = preprocessor.transform(df_clean[EXPECTED_RAW_FEATURES])

    has_proba = hasattr(model, "predict_proba")
    if has_proba:
        probs = model.predict_proba(X_trans)
        prob_attack = probs[:, 1]
        pred_labels = (prob_attack >= threshold).astype(int)
    else:
        pred_labels = model.predict(X_trans).astype(int)
        prob_attack = pred_labels.astype(float)

    results = pd.DataFrame({
        "predicted_label": pred_labels,
        "predicted_class": np.where(pred_labels == 1, "Attack", "Normal"),
        "probability_attack": np.round(prob_attack, 4),
        "is_alert": pred_labels == 1,
    }, index=df_raw.index)

    return results
