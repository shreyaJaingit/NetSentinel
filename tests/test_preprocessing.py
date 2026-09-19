"""
NetSentinel - Automated Unit Tests for Data Preprocessing (Phase 2)
"""
import numpy as np
import pandas as pd
import pytest
from sklearn.compose import ColumnTransformer

from src.config import (
    CATEGORICAL_FEATURES,
    EXPECTED_RAW_FEATURES,
    NUMERICAL_FEATURES,
    TARGET_BINARY,
    TARGET_MULTICLASS,
)
from src.data.preprocessing import (
    clean_raw_dataframe,
    create_preprocessor,
    load_preprocessor_bundle,
    prepare_features_and_labels,
    save_preprocessor_bundle,
)


@pytest.fixture
def sample_raw_dataframe():
    """Generates a minimal synthetic DataFrame mimicking UNSW-NB15 raw schema."""
    data = {
        "id": [1, 2, 3],
        "proto": ["tcp", "udp", "tcp"],
        "service": ["http", "-", "dns "],  # Test '-' and trailing whitespace
        "state": ["FIN", "CON", "INT"],
        "attack_cat": ["Normal", "DoS", "Normal"],
        "label": [0, 1, 0],
    }
    # Add all 39 numerical features with dummy values
    for feat in NUMERICAL_FEATURES:
        data[feat] = [10.0, 20.0, 30.0]

    return pd.DataFrame(data)


def test_clean_raw_dataframe(sample_raw_dataframe):
    """Verify that service='-' is remapped to 'none' and whitespace is stripped."""
    df_cleaned = clean_raw_dataframe(sample_raw_dataframe)

    assert df_cleaned["service"].iloc[1] == "none", "Failed to remap '-' to 'none' in service"
    assert df_cleaned["service"].iloc[2] == "dns", "Failed to strip trailing whitespace in service"
    assert df_cleaned["proto"].iloc[0] == "tcp"


def test_prepare_features_and_labels_prevents_leakage(sample_raw_dataframe):
    """Verify target and index columns are strictly removed from input feature matrix X."""
    X, y_bin, y_multi = prepare_features_and_labels(sample_raw_dataframe, is_training=True)

    # Assertions on feature isolation (Leakage prevention)
    assert "id" not in X.columns, "Target leakage: 'id' column was not dropped!"
    assert TARGET_BINARY not in X.columns, "Critical leakage: 'label' is in features X!"
    assert TARGET_MULTICLASS not in X.columns, "Critical leakage: 'attack_cat' is in features X!"

    # Assertions on targets
    assert list(y_bin) == [0, 1, 0]
    assert list(y_multi) == ["Normal", "DoS", "Normal"]

    # Assertions on feature set
    assert list(X.columns) == EXPECTED_RAW_FEATURES
    assert X.shape == (3, len(EXPECTED_RAW_FEATURES))


def test_prepare_features_raises_on_missing_columns():
    """Verify ValueError is raised if input data lacks required features."""
    incomplete_df = pd.DataFrame({"proto": ["tcp"], "service": ["http"]})
    with pytest.raises(ValueError, match="missing required features"):
        prepare_features_and_labels(incomplete_df)


def test_unseen_categorical_values_handled_gracefully():
    """
    Verify that unseen categories (e.g. 'ACC' or 'CLO' in test set)
    do NOT raise ValueError and are encoded as zero vectors.
    """
    train_data = pd.DataFrame({
        "proto": ["tcp", "udp"],
        "service": ["http", "dns"],
        "state": ["FIN", "CON"],
    })
    for col in NUMERICAL_FEATURES:
        train_data[col] = [1.0, 2.0]

    test_data_oov = pd.DataFrame({
        "proto": ["tcp", "newproto"],  # 'newproto' is unseen
        "service": ["http", "none"],
        "state": ["ACC", "CLO"],       # 'ACC' and 'CLO' are unseen
    })
    for col in NUMERICAL_FEATURES:
        test_data_oov[col] = [1.5, 2.5]

    preprocessor = create_preprocessor()
    X_train_trans = preprocessor.fit_transform(train_data[EXPECTED_RAW_FEATURES])

    # Transform unseen test data without crashing
    X_test_trans = preprocessor.transform(test_data_oov[EXPECTED_RAW_FEATURES])

    assert X_train_trans.shape[1] == X_test_trans.shape[1]
    assert not np.isnan(X_test_trans).any(), "NaN found in transformed unseen categories!"


def test_numerical_scaling_fits_only_on_train():
    """Verify that StandardScaler uses training mean/std, not test statistics."""
    train_data = pd.DataFrame({
        "proto": ["tcp", "tcp"],
        "service": ["http", "http"],
        "state": ["FIN", "FIN"],
    })
    test_data = train_data.copy()

    for col in NUMERICAL_FEATURES:
        train_data[col] = [0.0, 10.0]   # mean=5.0, std=5.0
        test_data[col] = [100.0, 200.0] # drastically different scale

    preprocessor = create_preprocessor()
    preprocessor.fit(train_data[EXPECTED_RAW_FEATURES])

    # Inspect scaler parameters
    scaler = preprocessor.named_transformers_["num"]
    np.testing.assert_allclose(scaler.mean_, np.full(len(NUMERICAL_FEATURES), 5.0))

    # Transform test data using training parameters (100 - 5) / 5 = 19.0
    test_trans = preprocessor.transform(test_data[EXPECTED_RAW_FEATURES])
    # The first 39 columns are the scaled numericals
    np.testing.assert_allclose(test_trans[0, :len(NUMERICAL_FEATURES)], np.full(len(NUMERICAL_FEATURES), 19.0))


def test_preprocessor_serialization_roundtrip(tmp_path, sample_raw_dataframe):
    """Verify saving and loading the preprocessor bundle reproduces identical transformations."""
    X, _, _ = prepare_features_and_labels(sample_raw_dataframe)

    preprocessor = create_preprocessor()
    X_trans_original = preprocessor.fit_transform(X)

    save_path = tmp_path / "preprocessor_test.joblib"
    save_preprocessor_bundle(preprocessor, save_path, {"test_meta": 42})

    bundle = load_preprocessor_bundle(save_path)
    loaded_preprocessor = bundle["preprocessor"]
    assert bundle["metadata"]["test_meta"] == 42

    X_trans_loaded = loaded_preprocessor.transform(X)
    np.testing.assert_allclose(X_trans_original, X_trans_loaded)
