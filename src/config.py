"""
NetSentinel - Global Configuration & Feature Contracts
"""
from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Dataset Files
TRAIN_DATA_PATH = DATA_DIR / "UNSW_NB15_training-set.csv"
TEST_DATA_PATH = DATA_DIR / "UNSW_NB15_testing-set.csv"

# Serialized Artifact Paths
PREPROCESSOR_PATH = MODELS_DIR / "preprocessor.joblib"
MODEL_PATH = MODELS_DIR / "baseline_model.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"

# Target & Identifier Column Contracts
TARGET_BINARY = "label"
TARGET_MULTICLASS = "attack_cat"
DROP_COLUMNS = ["id"]

# Categorical Features
CATEGORICAL_FEATURES = ["proto", "service", "state"]

# Numerical Features (39 features in UNSW-NB15)
NUMERICAL_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean",
    "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm",
    "ct_srv_dst", "is_sm_ips_ports"
]

# Complete list of expected input raw features (42 features: 39 numerical + 3 categorical)
EXPECTED_RAW_FEATURES = CATEGORICAL_FEATURES + NUMERICAL_FEATURES
