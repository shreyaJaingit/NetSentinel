# NetSentinel - Model Artifacts Directory

This directory stores serialized machine learning models and preprocessing pipelines.

## Artifact Policies
1. **Ignored by Git**: Serialized binaries (`.joblib`, `.pkl`) are ignored by `.gitignore`.
2. **Version Pairing**: Preprocessing pipelines (e.g. scalers, encoders) and trained classifiers must always be saved and loaded together as matched artifact pairs to prevent feature skew and data drift.
3. **Reproducibility**: Artifacts will be generated deterministically via scripts in `src/detection/train.py` using fixed random seeds.
