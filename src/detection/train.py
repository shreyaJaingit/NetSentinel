"""
NetSentinel - Model Training Module

Trains reproducible baseline classifiers (Logistic Regression and Decision Tree)
for binary network intrusion detection.
"""
from pathlib import Path
from typing import Any, Dict, Optional, Union

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier


def train_logistic_regression(
    X_train: np.ndarray,
    y_train: np.ndarray,
    random_state: int = 42,
    max_iter: int = 1000,
    C: float = 1.0,
    class_weight: Optional[Union[str, dict]] = None,
    solver: str = "lbfgs",
) -> LogisticRegression:
    """
    Trains a Logistic Regression baseline classifier.
    
    Parameters:
    - X_train: Preprocessed numerical feature matrix.
    - y_train: Binary target vector (0 = Normal, 1 = Attack).
    - random_state: Reproducible random seed.
    - max_iter: Maximum solver iterations to ensure convergence on scaled data.
    - C: Regularization strength (inverse of lambda).
    - class_weight: Optional class weights ('balanced' or custom dict).
    """
    model = LogisticRegression(
        C=C,
        max_iter=max_iter,
        random_state=random_state,
        class_weight=class_weight,
        solver=solver,
    )
    model.fit(X_train, y_train)
    return model


def train_decision_tree(
    X_train: np.ndarray,
    y_train: np.ndarray,
    random_state: int = 42,
    max_depth: Optional[int] = 10,
    min_samples_split: int = 20,
    min_samples_leaf: int = 10,
    class_weight: Optional[Union[str, dict]] = None,
) -> DecisionTreeClassifier:
    """
    Trains an interpretable Decision Tree classifier with controlled depth
    to prevent memorization and extreme overfitting.
    
    Parameters:
    - X_train: Preprocessed numerical feature matrix.
    - y_train: Binary target vector.
    - random_state: Reproducible random seed.
    - max_depth: Maximum tree depth to constrain tree complexity.
    - min_samples_split: Minimum samples required to split an internal node.
    - min_samples_leaf: Minimum samples required to be at a leaf node.
    - class_weight: Optional class weights.
    """
    model = DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        min_samples_leaf=min_samples_leaf,
        class_weight=class_weight,
        random_state=random_state,
    )
    model.fit(X_train, y_train)
    return model


def save_model_bundle(
    model: Any,
    output_path: Union[str, Path],
    model_name: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Serializes a trained model with configuration metadata.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    bundle = {
        "model": model,
        "model_name": model_name,
        "metadata": metadata or {},
    }
    joblib.dump(bundle, output_path)


def load_model_bundle(artifact_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Loads a serialized model bundle from disk.
    """
    artifact_path = Path(artifact_path)
    if not artifact_path.exists():
        raise FileNotFoundError(f"Model artifact not found at {artifact_path}")

    return joblib.load(artifact_path)
