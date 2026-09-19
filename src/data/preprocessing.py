"""
NetSentinel - Data Preprocessing & Pipeline Construction

Handles raw DataFrame cleaning, target separation, leakage prevention,
and Scikit-Learn ColumnTransformer pipeline building.
"""
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from src.config import (
    CATEGORICAL_FEATURES,
    DROP_COLUMNS,
    EXPECTED_RAW_FEATURES,
    NUMERICAL_FEATURES,
    TARGET_BINARY,
    TARGET_MULTICLASS,
)


def clean_raw_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans raw network flow records:
    - Strips whitespace from categorical columns.
    - Remaps service placeholder '-' to 'none'.
    - Fills any blank/empty strings with 'unknown'.
    """
    df_clean = df.copy()

    # Clean categorical string columns
    for col in CATEGORICAL_FEATURES:
        if col in df_clean.columns:
            # Strip outer whitespace
            df_clean[col] = df_clean[col].astype(str).str.strip()
            # Handle '-' in service: it indicates no application-layer service was matched
            if col == "service":
                df_clean[col] = df_clean[col].replace({"-": "none", "": "none"})
            else:
                df_clean[col] = df_clean[col].replace({"": "unknown"})

    return df_clean


def prepare_features_and_labels(
    df: pd.DataFrame,
    is_training: bool = True,
) -> Tuple[pd.DataFrame, Optional[pd.Series], Optional[pd.Series]]:
    """
    Prepares input features X and target labels y from a raw DataFrame:
    - Cleans values using clean_raw_dataframe.
    - Drops 'id' column to prevent row index memorization.
    - Strictly isolates target labels ('label' and 'attack_cat') from features X
      to eliminate data and target leakage.
    - Verifies that all expected features are present in X in deterministic order.
    """
    df_clean = clean_raw_dataframe(df)

    # 1. Extract Target Labels (if present)
    y_binary = None
    y_multiclass = None

    if TARGET_BINARY in df_clean.columns:
        y_binary = df_clean[TARGET_BINARY].copy()

    if TARGET_MULTICLASS in df_clean.columns:
        y_multiclass = df_clean[TARGET_MULTICLASS].astype(str).str.strip().copy()

    # 2. Drop identifiers and target labels from features X
    cols_to_drop = [col for col in DROP_COLUMNS + [TARGET_BINARY, TARGET_MULTICLASS] if col in df_clean.columns]
    X = df_clean.drop(columns=cols_to_drop)

    # 3. Ensure all expected raw features are present in X
    missing_features = [col for col in EXPECTED_RAW_FEATURES if col not in X.columns]
    if missing_features:
        raise ValueError(
            f"Input DataFrame is missing required features: {missing_features}. "
            f"Expected {len(EXPECTED_RAW_FEATURES)} features."
        )

    # 4. Enforce deterministic column ordering
    X = X[EXPECTED_RAW_FEATURES].copy()

    return X, y_binary, y_multiclass


def create_preprocessor(
    categorical_features: List[str] = CATEGORICAL_FEATURES,
    numerical_features: List[str] = NUMERICAL_FEATURES,
) -> ColumnTransformer:
    """
    Constructs a Scikit-learn ColumnTransformer:
    - Numerical features: Scaled via StandardScaler (fit strictly on training data).
    - Categorical features: Encoded via OneHotEncoder with handle_unknown='ignore'
      to gracefully handle out-of-vocabulary categories (e.g. 'ACC', 'CLO') during inference.
    """
    numerical_transformer = StandardScaler()
    categorical_transformer = OneHotEncoder(
        handle_unknown="ignore",
        sparse_output=False,
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numerical_transformer, numerical_features),
            ("cat", categorical_transformer, categorical_features),
        ],
        remainder="drop",  # Drop any unexpected columns
        verbose_feature_names_out=False,
    )

    return preprocessor


def save_preprocessor_bundle(
    preprocessor: ColumnTransformer,
    output_path: Union[str, Path],
    feature_metadata: Optional[Dict] = None,
) -> None:
    """
    Serializes the fitted preprocessor along with feature contract metadata.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    bundle = {
        "preprocessor": preprocessor,
        "metadata": feature_metadata or {},
    }
    joblib.dump(bundle, output_path)


def load_preprocessor_bundle(artifact_path: Union[str, Path]) -> Dict:
    """
    Loads the serialized preprocessor bundle from disk.
    """
    artifact_path = Path(artifact_path)
    if not artifact_path.exists():
        raise FileNotFoundError(f"Preprocessor artifact not found at {artifact_path}")

    bundle = joblib.load(artifact_path)
    return bundle
