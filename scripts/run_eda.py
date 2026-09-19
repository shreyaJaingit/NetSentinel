"""
NetSentinel Phase 1 - Exploratory Data Analysis (EDA) Script

Reads the verified UNSW-NB15 training and testing CSVs dynamically,
analyzes missingness, duplicates, data types, categorical distributions,
numerical ranges, anomalies, and potential leakage risks.
"""

import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")  # Headless backend for automated script execution
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

DATA_DIR = Path("data")
REPORTS_DIR = Path("reports/eda")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_PATH = DATA_DIR / "UNSW_NB15_training-set.csv"
TEST_PATH = DATA_DIR / "UNSW_NB15_testing-set.csv"


def run_eda():
    print("=" * 80)
    print("NetSentinel Phase 1: Dynamic Exploratory Data Analysis (EDA)")
    print("=" * 80)

    # 1. Verify existence of files
    if not TRAIN_PATH.exists() or not TEST_PATH.exists():
        raise FileNotFoundError(f"Dataset files missing in {DATA_DIR}. Run download first.")

    print(f"\n[1] Loading datasets...")
    print(f"    Train: {TRAIN_PATH}")
    print(f"    Test:  {TEST_PATH}")
    df_train = pd.read_csv(TRAIN_PATH)
    df_test = pd.read_csv(TEST_PATH)

    print(f"    Train shape: {df_train.shape[0]:,} rows, {df_train.shape[1]} columns")
    print(f"    Test shape:  {df_test.shape[0]:,} rows, {df_test.shape[1]} columns")

    # 2. Schema Parity Check
    print("\n[2] Checking Schema Parity...")
    train_cols = list(df_train.columns)
    test_cols = list(df_test.columns)
    cols_match = train_cols == test_cols
    print(f"    Identical column names and order: {cols_match}")
    if not cols_match:
        diff_train = set(train_cols) - set(test_cols)
        diff_test = set(test_cols) - set(train_cols)
        print(f"    In train but not test: {diff_train}")
        print(f"    In test but not train: {diff_test}")

    # Check dtypes parity
    dtype_mismatches = {}
    for col in train_cols:
        if df_train[col].dtype != df_test[col].dtype:
            dtype_mismatches[col] = {
                "train_dtype": str(df_train[col].dtype),
                "test_dtype": str(df_test[col].dtype),
            }
    print(f"    Data type mismatches between train and test: {len(dtype_mismatches)}")
    if dtype_mismatches:
        print(f"    Details: {dtype_mismatches}")

    # 3. Missing / Null Values
    print("\n[3] Inspecting Missing and Infinite Values...")
    train_nulls = df_train.isnull().sum()
    test_nulls = df_test.isnull().sum()
    train_null_cols = train_nulls[train_nulls > 0]
    test_null_cols = test_nulls[test_nulls > 0]
    print(f"    Train columns with null values: {len(train_null_cols)}")
    print(f"    Test columns with null values:  {len(test_null_cols)}")

    # Check for Inf / -Inf in numeric columns
    numeric_cols = df_train.select_dtypes(include=[np.number]).columns.tolist()
    train_infs = {col: int(np.isinf(df_train[col]).sum()) for col in numeric_cols if np.isinf(df_train[col]).sum() > 0}
    test_infs = {col: int(np.isinf(df_test[col]).sum()) for col in numeric_cols if np.isinf(df_test[col]).sum() > 0}
    print(f"    Train columns with infinite values: {len(train_infs)}")
    print(f"    Test columns with infinite values:  {len(test_infs)}")

    # 4. Duplicate Rows
    print("\n[4] Checking Duplicate Records...")
    exact_train_dups = int(df_train.duplicated().sum())
    exact_test_dups = int(df_test.duplicated().sum())
    # Duplicates excluding 'id' (since 'id' is artificially unique per file)
    feat_cols = [c for c in train_cols if c != "id"]
    content_train_dups = int(df_train.duplicated(subset=feat_cols).sum())
    content_test_dups = int(df_test.duplicated(subset=feat_cols).sum())
    print(f"    Exact row duplicates (including 'id'): Train={exact_train_dups}, Test={exact_test_dups}")
    print(f"    Flow feature duplicates (excluding 'id'): Train={content_train_dups:,} ({content_train_dups/len(df_train):.2%}), Test={content_test_dups:,} ({content_test_dups/len(df_test):.2%})")

    # 5. Categorical Features & Out-of-Vocabulary (OOV) Analysis
    print("\n[5] Categorical Feature Distributions & Vocabulary Overlap...")
    cat_cols = df_train.select_dtypes(include=["object"]).columns.tolist()
    print(f"    Categorical columns identified: {cat_cols}")

    cat_analysis = {}
    for col in cat_cols:
        train_unique = set(df_train[col].dropna().unique())
        test_unique = set(df_test[col].dropna().unique())
        unseen_in_test = test_unique - train_unique
        unseen_in_train = train_unique - test_unique

        # Check for empty spaces or hyphens as placeholders
        hyphen_count_train = int((df_train[col] == "-").sum())
        space_count_train = int((df_train[col].astype(str).str.strip() == "").sum())

        cat_analysis[col] = {
            "train_unique_count": len(train_unique),
            "test_unique_count": len(test_unique),
            "unseen_in_test_count": len(unseen_in_test),
            "unseen_in_test_examples": list(unseen_in_test)[:5],
            "unseen_in_train_count": len(unseen_in_train),
            "hyphen_placeholder_count_train": hyphen_count_train,
            "empty_string_count_train": space_count_train,
        }
        print(f"    Column '{col}':")
        print(f"      Train unique: {len(train_unique)}, Test unique: {len(test_unique)}")
        if unseen_in_test:
            print(f"      [WARNING] Categories in test but NOT in train ({len(unseen_in_test)}): {list(unseen_in_test)[:5]}")
        if hyphen_count_train > 0:
            print(f"      [INFO] Uses '-' as placeholder in train: {hyphen_count_train:,} rows ({hyphen_count_train/len(df_train):.2%})")

    # 6. Target Variable Analysis
    print("\n[6] Target Variable Distributions...")
    train_label_dist = df_train["label"].value_counts().to_dict()
    test_label_dist = df_test["label"].value_counts().to_dict()
    train_attack_dist = df_train["attack_cat"].value_counts().to_dict()
    test_attack_dist = df_test["attack_cat"].value_counts().to_dict()

    print("    Binary 'label' in Train:")
    for k, v in train_label_dist.items():
        print(f"      Class {k} ({'Attack' if k==1 else 'Normal'}): {v:,} ({v/len(df_train):.2%})")
    print("    Binary 'label' in Test:")
    for k, v in test_label_dist.items():
        print(f"      Class {k} ({'Attack' if k==1 else 'Normal'}): {v:,} ({v/len(df_test):.2%})")

    # Check attack_cat vs label alignment
    normal_has_label_0 = (df_train[df_train["attack_cat"] == "Normal"]["label"] == 0).all()
    attack_has_label_1 = (df_train[df_train["attack_cat"] != "Normal"]["label"] == 1).all()
    print(f"    Label alignment (Normal == 0 & Attack != Normal == 1): {normal_has_label_0 and attack_has_label_1}")

    # 7. Constant & Quasi-Constant Features
    print("\n[7] Constant and Quasi-Constant Feature Check...")
    constant_cols = []
    quasi_constant_cols = []  # >99.5% single value
    for col in train_cols:
        top_freq_ratio = df_train[col].value_counts(normalize=True, dropna=False).iloc[0]
        if top_freq_ratio == 1.0:
            constant_cols.append(col)
        elif top_freq_ratio >= 0.995:
            top_val = df_train[col].value_counts(dropna=False).index[0]
            quasi_constant_cols.append((col, float(top_freq_ratio), str(top_val)))

    print(f"    Strictly constant columns: {constant_cols}")
    print(f"    Quasi-constant columns (>99.5% single value): {len(quasi_constant_cols)}")
    for col, ratio, val in quasi_constant_cols:
        print(f"      {col}: {ratio:.2%} are '{val}'")

    # 8. Numerical Feature Outlier & Range Inspection
    print("\n[8] Numerical Feature Ranges & Extremes...")
    num_summary = {}
    for col in numeric_cols:
        if col in ["id", "label"]:
            continue
        c_min = float(df_train[col].min())
        c_max = float(df_train[col].max())
        c_median = float(df_train[col].median())
        c_mean = float(df_train[col].mean())
        c_std = float(df_train[col].std())
        num_summary[col] = {
            "min": c_min,
            "max": c_max,
            "median": c_median,
            "mean": c_mean,
            "std": c_std,
        }

    # Identify heavy skew / extreme dynamic range
    high_dynamic_range = []
    for col, stats in num_summary.items():
        if stats["max"] > 0 and stats["min"] >= 0 and stats["max"] / (stats["median"] + 1e-6) > 1000:
            high_dynamic_range.append(col)
    print(f"    Features with extreme dynamic range (max/median > 1000): {len(high_dynamic_range)}")
    print(f"    Examples: {high_dynamic_range[:8]}")

    # 9. Potential Data Leakage Audit
    print("\n[9] Data Leakage & Machine Learning Audit...")
    print("    [!] 'id' column: Sequential index. Must be dropped prior to modeling.")
    print("    [!] 'attack_cat' column: Contains multiclass label. Must NOT be an input feature for binary classification.")
    print("    [!] Categorical encoding: 'proto' has unseen protocols in test set. Scaler/encoder must handle unknown categories gracefully.")

    # 10. Generate Visualizations
    print("\n[10] Generating EDA Visualizations...")
    # Plot 1: Binary Class Distribution
    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(2)
    width = 0.35
    ax.bar(x - width/2, [train_label_dist[0], train_label_dist[1]], width, label="Train", color="#1f77b4")
    ax.bar(x + width/2, [test_label_dist[0], test_label_dist[1]], width, label="Test", color="#ff7f0e")
    ax.set_xticks(x)
    ax.set_xticklabels(["Normal (0)", "Attack (1)"])
    ax.set_ylabel("Record Count")
    ax.set_title("UNSW-NB15 Binary Class Distribution (Train vs. Test)")
    ax.legend()
    plt.tight_layout()
    plot_path_binary = REPORTS_DIR / "class_distribution.png"
    plt.savefig(plot_path_binary, dpi=150)
    plt.close()
    print(f"    Saved: {plot_path_binary}")

    # Plot 2: Multiclass Attack Categories (Train)
    fig, ax = plt.subplots(figsize=(10, 5))
    attack_series = df_train["attack_cat"].value_counts()
    attack_series.plot(kind="bar", ax=ax, color="#2ca02c", edgecolor="black")
    ax.set_title("UNSW-NB15 Attack Category Frequency in Training Set")
    ax.set_ylabel("Flow Count")
    ax.set_xlabel("Category")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plot_path_attack = REPORTS_DIR / "attack_categories.png"
    plt.savefig(plot_path_attack, dpi=150)
    plt.close()
    print(f"    Saved: {plot_path_attack}")

    # 11. Save JSON & Text Summary
    summary_data = {
        "train_rows": len(df_train),
        "test_rows": len(df_test),
        "columns_count": len(train_cols),
        "schema_match": cols_match,
        "dtype_mismatches": dtype_mismatches,
        "train_null_columns": list(train_null_cols.index),
        "test_null_columns": list(test_null_cols.index),
        "exact_duplicates_train": exact_train_dups,
        "content_duplicates_train": content_train_dups,
        "categorical_columns": cat_analysis,
        "train_label_distribution": train_label_dist,
        "test_label_distribution": test_label_dist,
        "train_attack_distribution": train_attack_dist,
        "test_attack_distribution": test_attack_dist,
        "constant_columns": constant_cols,
        "quasi_constant_columns": quasi_constant_cols,
        "high_dynamic_range_columns": high_dynamic_range,
    }

    json_path = REPORTS_DIR / "eda_summary.json"
    with open(json_path, "w") as f:
        json.dump(summary_data, f, indent=2)
    print(f"    Saved JSON summary: {json_path}")

    print("\n" + "=" * 80)
    print("EDA Complete. All reports and figures generated successfully.")
    print("=" * 80)


if __name__ == "__main__":
    run_eda()
