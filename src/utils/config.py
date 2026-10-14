"""
NetSentinel Robust Configuration Loader
Parses YAML and JSON configurations cleanly with zero required external dependencies.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "kafka": {
        "bootstrap_servers": ["localhost:9092"],
        "telemetry_topic": "network-telemetry",
        "alerts_topic": "threat-alerts",
        "linger_ms": 10,
        "acks": 1,
        "compression_type": "gzip",
        "consumer_group": "netsentinel-inference-group",
        "batch_size": 100,
        "auto_offset_reset": "latest"
    },
    "sniffer": {
        "interface": None,
        "flow_timeout": 15.0,
        "active_timeout": 60.0,
        "bpf_filter": "ip",
        "promiscuous": True
    },
    "inference": {
        "model_path": "models/unsw_nb15_model.onnx",
        "anomaly_threshold": 0.85,
        "shap_max_background_samples": 50,
        "shap_top_features_count": 3,
        "execution_provider": "CPUExecutionProvider"
    },
    "mitigation": {
        "rules_snort3_path": "rules/netsentinel_snort3.rules",
        "rules_suricata_path": "rules/netsentinel_suricata.rules",
        "base_sid": 1000001,
        "webhook_url": "https://localhost:8443/api/v1/mitigation/alert",
        "mtls": {
            "enabled": True,
            "ca_cert": "certs/ca.crt",
            "client_cert": "certs/client.crt",
            "client_key": "certs/client.key"
        },
        "firewall": {
            "backend": "nftables",
            "default_ttl_seconds": 3600,
            "gvisor_runtime": "runsc",
            "dry_run": True
        }
    },
    "monitoring": {
        "port": 8000,
        "host": "0.0.0.0",
        "metrics_path": "/metrics"
    }
}


def _parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Lightweight zero-dependency YAML parser for nested dictionaries, lists, and primitives."""
    result: Dict[str, Any] = {}
    # stack of [indent, dict, last_inserted_key]
    stack: list[list[Any]] = [[-1, result, ""]]

    for raw_line in text.splitlines():
        line = re.sub(r'#.*$', '', raw_line).rstrip()
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        # Handle list item
        if stripped.startswith("- "):
            val = stripped[2:].strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            parent = stack[-1][1]
            last_key = stack[-1][2]
            if last_key:
                if not isinstance(parent.get(last_key), list):
                    parent[last_key] = []
                parent[last_key].append(val)
            continue

        if ":" not in stripped:
            continue

        key, val = stripped.split(":", 1)
        key = key.strip()
        val = val.strip()

        while stack and stack[-1][0] >= indent:
            stack.pop()

        parent_dict = stack[-1][1]
        stack[-1][2] = key

        if val == "":
            new_dict: Dict[str, Any] = {}
            parent_dict[key] = new_dict
            stack.append([indent, new_dict, ""])
        else:
            parsed_val: Any = val
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                parsed_val = val[1:-1]
            elif val.lower() == "true":
                parsed_val = True
            elif val.lower() == "false":
                parsed_val = False
            elif val.lower() in ("null", "none"):
                parsed_val = None
            else:
                try:
                    if "." in val or "e" in val.lower():
                        parsed_val = float(val)
                    else:
                        parsed_val = int(val)
                except ValueError:
                    parsed_val = val
            parent_dict[key] = parsed_val

    return result


def load_config(path: str = "config/config.yaml") -> Dict[str, Any]:
    """Load config from path, falling back to JSON or default dictionary."""
    if not os.path.exists(path):
        return DEFAULT_CONFIG

    try:
        try:
            import yaml  # type: ignore
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except ImportError:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            return _parse_simple_yaml(content)
    except Exception as e:
        print(f"Warning: Failed to parse {path} ({e}), using default configuration.")
        return DEFAULT_CONFIG
