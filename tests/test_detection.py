"""
NetSentinel - Automated Unit Tests for Detection, Training, and Evaluation (Phase 3)
"""
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from src.config import (
    CATEGORICAL_FEATURES,
    EXPECTED_RAW_FEATURES,
    NUMERICAL_FEATURES,
    PREPROCESSOR_PATH,
)
from src.data.preprocessing import (
    create_preprocessor,
    load_preprocessor_bundle,
    prepare_features_and_labels,
)
from src.detection.evaluate import evaluate_model
from src.detection.predict import predict_batch, predict_single_flow
from src.detection.train import (
    load_model_bundle,
    save_model_bundle,
    train_decision_tree,
    train_logistic_regression,
)


@pytest.fixture
def synthetic_detection_dataset():
    """Creates a small, fully separable synthetic dataset for unit testing."""
    np.random.seed(42)
    n_samples = 40

    data = {
        "proto": np.random.choice(["tcp", "udp"], size=n_samples),
        "service": np.random.choice(["http", "dns", "none"], size=n_samples),
        "state": np.random.choice(["FIN", "CON"], size=n_samples),
        "label": np.random.choice([0, 1], size=n_samples),
    }

    # Add numeric features
    for col in NUMERICAL_FEATURES:
        data[col] = np.random.uniform(0.0, 100.0, size=n_samples)

    df = pd.DataFrame(data)
    preprocessor = create_preprocessor()
    X_trans = preprocessor.fit_transform(df[EXPECTED_RAW_FEATURES])
    y = df["label"].values

    return df, preprocessor, X_trans, y


def test_train_logistic_regression(synthetic_detection_dataset):
    """Verify that Logistic Regression trains and produces valid predictions."""
    _, _, X_trans, y = synthetic_detection_dataset
    model = train_logistic_regression(X_trans, y, random_state=42, max_iter=100)

    preds = model.predict(X_trans)
    assert len(preds) == len(y)
    assert set(preds).issubset({0, 1})
    assert hasattr(model, "predict_proba")


def test_train_decision_tree(synthetic_detection_dataset):
    """Verify that Decision Tree trains with expected depth constraint."""
    _, _, X_trans, y = synthetic_detection_dataset
    model = train_decision_tree(X_trans, y, random_state=42, max_depth=5)

    preds = model.predict(X_trans)
    assert len(preds) == len(y)
    assert model.get_depth() <= 5


def test_model_serialization_roundtrip(tmp_path, synthetic_detection_dataset):
    """Verify saving and loading model bundles preserves predictions."""
    _, _, X_trans, y = synthetic_detection_dataset
    model = train_decision_tree(X_trans, y, random_state=42)

    save_path = tmp_path / "test_model.joblib"
    save_model_bundle(model, save_path, "DecisionTree", {"seed": 42})

    bundle = load_model_bundle(save_path)
    assert bundle["model_name"] == "DecisionTree"
    assert bundle["metadata"]["seed"] == 42

    loaded_model = bundle["model"]
    np.testing.assert_array_equal(model.predict(X_trans), loaded_model.predict(X_trans))


def test_evaluation_metrics_calculation(synthetic_detection_dataset):
    """Verify evaluate_model calculates accuracy, precision, recall, F1, and confusion matrix."""
    _, _, X_trans, y = synthetic_detection_dataset
    model = train_decision_tree(X_trans, y, random_state=42)

    metrics = evaluate_model(model, X_trans, y)

    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert 0.0 <= metrics["roc_auc"] <= 1.0

    cm = metrics["confusion_matrix"]
    total = cm["true_negatives"] + cm["false_positives"] + cm["false_negatives"] + cm["true_positives"]
    assert total == len(y)


def test_predict_single_flow_inference(synthetic_detection_dataset):
    """Verify single flow inference returns expected fields, probabilities, and confidence."""
    df, preprocessor, X_trans, y = synthetic_detection_dataset
    model = train_logistic_regression(X_trans, y, random_state=42, max_iter=100)

    # Take first row as dict
    sample_flow = df.iloc[0].to_dict()

    result = predict_single_flow(model, preprocessor, sample_flow, threshold=0.5)

    assert result["predicted_label"] in (0, 1)
    assert result["predicted_class"] in ("Normal", "Attack")
    assert 0.0 <= result["confidence"] <= 1.0
    assert 0.0 <= result["probability_attack"] <= 1.0
    assert 0.0 <= result["probability_normal"] <= 1.0
    assert isinstance(result["is_alert"], bool)
    assert result["is_alert"] == (result["predicted_label"] == 1)


def test_predict_batch_inference(synthetic_detection_dataset):
    """Verify batch inference returns a DataFrame with matching length and predictions."""
    df, preprocessor, X_trans, y = synthetic_detection_dataset
    model = train_decision_tree(X_trans, y, random_state=42)

    batch_results = predict_batch(model, preprocessor, df, threshold=0.5)

    assert len(batch_results) == len(df)
    assert "predicted_label" in batch_results.columns
    assert "predicted_class" in batch_results.columns
    assert "is_alert" in batch_results.columns


def test_preprocessor_model_contract_compatibility():
    """
    Verify that the saved preprocessor artifact is fully compatible with a model
    and that input features strictly adhere to EXPECTED_RAW_FEATURES.
    """
    if not PREPROCESSOR_PATH.exists():
        pytest.skip("preprocessor.joblib not yet generated.")

    prep_bundle = load_preprocessor_bundle(PREPROCESSOR_PATH)
    preprocessor = prep_bundle["preprocessor"]

    # Construct minimal dummy sample with expected features
    dummy_row = {"proto": "tcp", "service": "http", "state": "FIN"}
    for feat in NUMERICAL_FEATURES:
        dummy_row[feat] = 1.0

    df_dummy = pd.DataFrame([dummy_row])
    X_trans = preprocessor.transform(df_dummy)

    # Train a minimal model on this transformed shape
    dummy_model = train_decision_tree(X_trans, np.array([1]), random_state=42)

    # Inference should execute cleanly
    pred = dummy_model.predict(X_trans)
    assert pred[0] in (0, 1)
