"""
NetSentinel Phase 2 - Preprocessing Pipeline Builder & Validator

Fits the preprocessor strictly on training data, validates inference on test data,
and saves the serialized preprocessor bundle to models/preprocessor.joblib.
"""
import sys
from pathlib import Path

# Ensure project root is on sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd

from src.config import (
    CATEGORICAL_FEATURES,
    EXPECTED_RAW_FEATURES,
    NUMERICAL_FEATURES,
    PREPROCESSOR_PATH,
    TEST_DATA_PATH,
    TRAIN_DATA_PATH,
)
from src.data.preprocessing import (
    create_preprocessor,
    load_preprocessor_bundle,
    prepare_features_and_labels,
    save_preprocessor_bundle,
)


def main():
    print("=" * 80)
    print("NetSentinel Phase 2: Fitting & Validating Preprocessor Pipeline")
    print("=" * 80)

    # 1. Load Training and Testing sets
    print(f"\n[1] Reading training data from {TRAIN_DATA_PATH}...")
    df_train = pd.read_csv(TRAIN_DATA_PATH)
    print(f"    Loaded {len(df_train):,} training records.")

    print(f"[2] Reading testing data from {TEST_DATA_PATH}...")
    df_test = pd.read_csv(TEST_DATA_PATH)
    print(f"    Loaded {len(df_test):,} testing records.")

    # 2. Extract features and target labels
    print("\n[3] Preparing features and target labels (eliminating leakage)...")
    X_train, y_train_bin, y_train_multi = prepare_features_and_labels(df_train, is_training=True)
    X_test, y_test_bin, y_test_multi = prepare_features_and_labels(df_test, is_training=False)

    print(f"    X_train shape: {X_train.shape} (strictly {len(EXPECTED_RAW_FEATURES)} features)")
    print(f"    X_test shape:  {X_test.shape} (strictly {len(EXPECTED_RAW_FEATURES)} features)")
    assert "id" not in X_train.columns, "Leakage: 'id' was not dropped from X_train!"
    assert "label" not in X_train.columns, "Leakage: 'label' was not dropped from X_train!"
    assert "attack_cat" not in X_train.columns, "Leakage: 'attack_cat' was not dropped from X_train!"

    # 3. Instantiate and Fit Preprocessor strictly on X_train
    print("\n[4] Fitting ColumnTransformer strictly on X_train...")
    preprocessor = create_preprocessor()
    X_train_trans = preprocessor.fit_transform(X_train)
    print(f"    X_train transformed shape: {X_train_trans.shape}")

    # 4. Transform X_test (Validating out-of-vocabulary handling for 'ACC' and 'CLO')
    print("\n[5] Transforming X_test using fitted parameters (testing OOV resiliency)...")
    X_test_trans = preprocessor.transform(X_test)
    print(f"    X_test transformed shape:  {X_test_trans.shape}")
    assert X_train_trans.shape[1] == X_test_trans.shape[1], "Transformed feature dimensionality mismatch!"
    print(f"    [OK] Successfully transformed test records without crashing on 'ACC'/'CLO'.")

    # 5. Extract Feature Names
    cat_encoder = preprocessor.named_transformers_["cat"]
    encoded_cat_features = list(cat_encoder.get_feature_names_out(CATEGORICAL_FEATURES))
    final_feature_names = NUMERICAL_FEATURES + encoded_cat_features
    print(f"\n[6] Transformed feature matrix dimensionality: {len(final_feature_names)} features")
    print(f"    - Numerical features scaled: {len(NUMERICAL_FEATURES)}")
    print(f"    - One-hot encoded features:  {len(encoded_cat_features)}")

    # 6. Save Bundle to models/preprocessor.joblib
    metadata = {
        "expected_raw_features": EXPECTED_RAW_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "numerical_features": NUMERICAL_FEATURES,
        "transformed_feature_names": final_feature_names,
        "train_samples_fitted": len(X_train),
        "total_transformed_dim": len(final_feature_names),
    }

    print(f"\n[7] Serializing preprocessor bundle to {PREPROCESSOR_PATH}...")
    save_preprocessor_bundle(preprocessor, PREPROCESSOR_PATH, metadata)
    print(f"    [OK] Saved successfully. File size: {PREPROCESSOR_PATH.stat().st_size:,} bytes")

    # 7. Verification: Load and verify round-trip
    print("\n[8] Verifying artifact round-trip loading...")
    bundle = load_preprocessor_bundle(PREPROCESSOR_PATH)
    loaded_prep = bundle["preprocessor"]
    test_sample = loaded_prep.transform(X_test.iloc[:5])
    assert test_sample.shape == (5, len(final_feature_names)), "Round-trip transformation mismatch!"
    print(f"    [OK] Loaded bundle verified. Successfully transformed test sample.")

    print("\n" + "=" * 80)
    print("Phase 2 Preprocessing Pipeline Build & Verification Complete.")
    print("=" * 80)


if __name__ == "__main__":
    main()
