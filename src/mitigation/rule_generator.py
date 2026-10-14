"""
NetSentinel Dynamic Rule Generator
Compiles real-time threat telemetry, anomaly probabilities, and SHAP-attributed root causes
into syntactically valid Snort 3 and Suricata IDS/IPS signatures.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..utils.config import load_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("NetSentinel.RuleGenerator")

# Standard Classtype mappings according to Snort/Suricata classifications
CLASSTYPE_MAP = {
    "DoS": "denial-of-service",
    "Exploits": "attempted-admin",
    "Reconnaissance": "network-scan",
    "Fuzzers": "misc-activity",
    "Generic": "bad-traffic",
    "Normal": "not-suspicious"
}


@dataclass
class GeneratedRule:
    """Represents a compiled IDS/IPS rule."""
    sid: int
    rev: int
    engine: str  # 'snort3' or 'suricata'
    rule_text: str
    attack_cat: str
    target_ip: str
    created_at: str


class DynamicRuleGenerator:
    """Automates compilation of streaming threat telemetry into Snort 3 and Suricata signatures."""

    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = load_config(config_path)
        mitigation_cfg = self.config.get("mitigation", {})

        self.snort3_path = mitigation_cfg.get("rules_snort3_path", "rules/netsentinel_snort3.rules")
        self.suricata_path = mitigation_cfg.get("rules_suricata_path", "rules/netsentinel_suricata.rules")
        self.current_sid = int(mitigation_cfg.get("base_sid", 1000001))

        os.makedirs(os.path.dirname(self.snort3_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.suricata_path), exist_ok=True)

        self._active_signatures: set[str] = set()

    def generate_signatures_from_alert(
        self, alert: Dict[str, Any]
    ) -> Tuple[GeneratedRule, GeneratedRule]:
        """
        Generate both Snort 3 and Suricata rules from an enriched threat alert.
        Returns: (snort3_rule, suricata_rule)
        """
        src_ip = alert.get("src_ip", "$EXTERNAL_NET")
        dst_ip = alert.get("dst_ip", "$HOME_NET")
        src_port = str(alert.get("src_port", "any"))
        dst_port = str(alert.get("dst_port", "any"))
        proto = alert.get("proto", "tcp").lower()
        if proto not in ("tcp", "udp", "icmp", "ip"):
            proto = "ip"

        attack_cat = alert.get("attack_cat", "Generic")
        primary_feature = alert.get("primary_contributing_feature", "traffic_anomaly")
        prob = float(alert.get("anomaly_prob", 0.95))
        classtype = CLASSTYPE_MAP.get(attack_cat, "bad-traffic")
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        sid = self.current_sid
        self.current_sid += 1
        rev = 1

        # Format Snort 3 Rule
        snort_opts = [
            f'msg:"[NetSentinel] {attack_cat} Attack Detected (Root-Cause: {primary_feature})"',
            f'classtype:{classtype}',
            f'sid:{sid}',
            f'rev:{rev}',
            f'metadata:created_at {timestamp}, confidence {prob:.2f}, engine NetSentinel_v1',
        ]

        if attack_cat == "DoS":
            snort_opts.append('threshold:type both, track by_src, count 50, seconds 5')
        elif attack_cat == "Reconnaissance":
            snort_opts.append('threshold:type both, track by_src, count 20, seconds 10')

        snort3_rule_text = f"alert {proto} {src_ip} {src_port} -> {dst_ip} {dst_port} ( {'; '.join(snort_opts)}; )"

        # Format Suricata Rule
        suricata_opts = [
            f'msg:"[NetSentinel] {attack_cat} Anomaly (Attr: {primary_feature})"',
            f'flow:to_server',
            f'classtype:{classtype}',
            f'sid:{sid}',
            f'rev:{rev}',
        ]
        if attack_cat == "DoS":
            suricata_opts.append('threshold:type threshold, track by_src, count 50, seconds 5')
        elif attack_cat == "Reconnaissance":
            suricata_opts.append('threshold:type threshold, track by_src, count 20, seconds 10')

        suricata_rule_text = f"alert {proto} {src_ip} {src_port} -> {dst_ip} {dst_port} ( {'; '.join(suricata_opts)}; )"

        snort_rule = GeneratedRule(
            sid=sid,
            rev=rev,
            engine="snort3",
            rule_text=snort3_rule_text,
            attack_cat=attack_cat,
            target_ip=src_ip,
            created_at=timestamp
        )

        suricata_rule = GeneratedRule(
            sid=sid,
            rev=rev,
            engine="suricata",
            rule_text=suricata_rule_text,
            attack_cat=attack_cat,
            target_ip=src_ip,
            created_at=timestamp
        )

        # Write to files
        self._append_rule(self.snort3_path, snort3_rule_text)
        self._append_rule(self.suricata_path, suricata_rule_text)

        logger.info(f"Generated Snort 3 & Suricata rules for SID {sid} targeting {src_ip} ({attack_cat})")
        return snort_rule, suricata_rule

    def _append_rule(self, filepath: str, rule_text: str) -> None:
        """Atomically append rule to target file."""
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(rule_text + "\n")

    def load_rules(self, filepath: str) -> List[str]:
        """Read existing rules from file."""
        if not os.path.exists(filepath):
            return []
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
