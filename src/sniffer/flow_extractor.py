"""
NetSentinel Flow Extractor & Telemetry Streamer
Aggregates raw packets into 5-tuple bi-directional network flows,
computes statistical features aligned with the UNSW-NB15 benchmark dataset schema,
and asynchronously streams structured JSON telemetry payloads into Apache Kafka.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import random
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..utils.config import load_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("NetSentinel.FlowExtractor")

# Try to import scapy; if unavailable or raw socket privileges are restricted, provide graceful fallbacks
try:
    from scapy.all import IP, TCP, UDP, ICMP, AsyncSniffer, Packet  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = Any
    logger.warning("Scapy not found. Live packet capture will require scapy to be installed.")

# Try to import kafka; fallback to mock producer if unavailable or broker down
try:
    from kafka import KafkaProducer  # type: ignore
    from kafka.errors import NoBrokersAvailable  # type: ignore
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    logger.warning("kafka-python not found. In-memory streaming fallback will be utilized.")


@dataclass
class PacketMetadata:
    """Metadata extracted from a single network packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    length: int
    ttl: int
    tcp_flags: Dict[str, bool] = field(default_factory=dict)
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_window: int = 0
    payload_len: int = 0


class NetworkFlow:
    """Represents a bi-directional network flow tracked by 5-tuple."""

    def __init__(self, key: Tuple[str, str, int, int, str], start_time: float):
        self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto = key
        self.start_time = start_time
        self.last_time = start_time
        self.state = "REQ"

        # Packet and byte counts (forward = src->dst, backward = dst->src)
        self.spkts = 0
        self.dpkts = 0
        self.sbytes = 0
        self.dbytes = 0

        # Packet sizes
        self.s_packet_lengths: List[int] = []
        self.d_packet_lengths: List[int] = []

        # Inter-packet arrival times
        self.s_inter_arrival_times: List[float] = []
        self.d_inter_arrival_times: List[float] = []
        self._s_prev_time: Optional[float] = None
        self._d_prev_time: Optional[float] = None

        # TTL values
        self.sttl = 0
        self.dttl = 0

        # TCP Specifics
        self.swin = 0
        self.dwin = 0
        self.stcpb = 0
        self.dtcpb = 0
        self.syn_time: Optional[float] = None
        self.synack_time: Optional[float] = None
        self.ack_time: Optional[float] = None

        # Retransmissions and drops (approximated)
        self.sloss = 0
        self.dloss = 0
        self._seen_s_seqs: set[int] = set()
        self._seen_d_seqs: set[int] = set()

        # Flag counters
        self.tcp_flags_count = {
            "SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0
        }

    def add_packet(self, pkt: PacketMetadata) -> None:
        """Add packet to flow and update internal counters."""
        is_forward = (pkt.src_ip == self.src_ip and pkt.src_port == self.src_port)
        self.last_time = max(self.last_time, pkt.timestamp)

        if is_forward:
            self.spkts += 1
            self.sbytes += pkt.length
            self.s_packet_lengths.append(pkt.length)
            self.sttl = pkt.ttl
            if self.swin == 0 and pkt.tcp_window > 0:
                self.swin = pkt.tcp_window
            if self.stcpb == 0 and pkt.tcp_seq > 0:
                self.stcpb = pkt.tcp_seq

            if self._s_prev_time is not None:
                self.s_inter_arrival_times.append(pkt.timestamp - self._s_prev_time)
            self._s_prev_time = pkt.timestamp

            if pkt.tcp_seq > 0:
                if pkt.tcp_seq in self._seen_s_seqs:
                    self.sloss += 1
                else:
                    self._seen_s_seqs.add(pkt.tcp_seq)

            if pkt.tcp_flags.get("SYN") and not pkt.tcp_flags.get("ACK"):
                self.syn_time = pkt.timestamp
                self.state = "REQ"
            elif pkt.tcp_flags.get("ACK") and self.synack_time and not self.ack_time:
                self.ack_time = pkt.timestamp
                self.state = "CON"

        else:
            self.dpkts += 1
            self.dbytes += pkt.length
            self.d_packet_lengths.append(pkt.length)
            self.dttl = pkt.ttl
            if self.dwin == 0 and pkt.tcp_window > 0:
                self.dwin = pkt.tcp_window
            if self.dtcpb == 0 and pkt.tcp_seq > 0:
                self.dtcpb = pkt.tcp_seq

            if self._d_prev_time is not None:
                self.d_inter_arrival_times.append(pkt.timestamp - self._d_prev_time)
            self._d_prev_time = pkt.timestamp

            if pkt.tcp_seq > 0:
                if pkt.tcp_seq in self._seen_d_seqs:
                    self.dloss += 1
                else:
                    self._seen_d_seqs.add(pkt.tcp_seq)

            if pkt.tcp_flags.get("SYN") and pkt.tcp_flags.get("ACK"):
                self.synack_time = pkt.timestamp
                self.state = "ACC"

        # Update TCP flags
        for flag_name, is_set in pkt.tcp_flags.items():
            if is_set and flag_name in self.tcp_flags_count:
                self.tcp_flags_count[flag_name] += 1

        if pkt.tcp_flags.get("FIN"):
            self.state = "FIN"
        elif pkt.tcp_flags.get("RST"):
            self.state = "RST"

    @property
    def duration(self) -> float:
        return max(0.0001, self.last_time - self.start_time)

    def compute_features(self, context_stats: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
        """Compute statistical features aligned with UNSW-NB15 schema."""
        dur = self.duration
        total_pkts = self.spkts + self.dpkts
        total_bytes = self.sbytes + self.dbytes

        # Service detection approximation
        port = min(self.src_port, self.dst_port)
        service_map = {
            80: "http", 443: "ssl", 53: "dns", 22: "ssh",
            21: "ftp", 25: "smtp", 110: "pop3", 143: "imap"
        }
        service = service_map.get(port, "-")

        # Rate calculations
        rate = total_pkts / dur if dur > 0 else 0.0
        sload = (self.sbytes * 8.0) / dur if dur > 0 else 0.0
        dload = (self.dbytes * 8.0) / dur if dur > 0 else 0.0

        # Mean packet sizes
        smean = (self.sbytes / self.spkts) if self.spkts > 0 else 0.0
        dmean = (self.dbytes / self.dpkts) if self.dpkts > 0 else 0.0

        # Packet size variance
        all_sizes = self.s_packet_lengths + self.d_packet_lengths
        if len(all_sizes) > 1:
            mean_size = sum(all_sizes) / len(all_sizes)
            pkt_size_var = sum((x - mean_size) ** 2 for x in all_sizes) / (len(all_sizes) - 1)
        else:
            pkt_size_var = 0.0

        # Inter-packet arrival times
        sinpkt = (sum(self.s_inter_arrival_times) / len(self.s_inter_arrival_times)) if self.s_inter_arrival_times else 0.0
        dinpkt = (sum(self.d_inter_arrival_times) / len(self.d_inter_arrival_times)) if self.d_inter_arrival_times else 0.0

        # Jitter calculations
        def calc_jitter(inter_times: List[float]) -> float:
            if len(inter_times) < 2:
                return 0.0
            diffs = [abs(inter_times[i] - inter_times[i - 1]) for i in range(1, len(inter_times))]
            return sum(diffs) / len(diffs)

        sjit = calc_jitter(self.s_inter_arrival_times)
        djit = calc_jitter(self.d_inter_arrival_times)

        # TCP connection setup times (RTT, SYN-ACK, ACK-DAT)
        synack = 0.0
        ackdat = 0.0
        tcprtt = 0.0
        if self.syn_time and self.synack_time:
            synack = max(0.0, self.synack_time - self.syn_time)
        if self.synack_time and self.ack_time:
            ackdat = max(0.0, self.ack_time - self.synack_time)
        tcprtt = synack + ackdat

        # TCP Flag ratios
        tcp_pkts = sum(self.tcp_flags_count.values()) or 1
        syn_ratio = self.tcp_flags_count["SYN"] / tcp_pkts
        ack_ratio = self.tcp_flags_count["ACK"] / tcp_pkts
        fin_ratio = self.tcp_flags_count["FIN"] / tcp_pkts
        rst_ratio = self.tcp_flags_count["RST"] / tcp_pkts

        # Connection context stats (sliding window counts)
        c_stats = context_stats or {}

        features = {
            # 5-Tuple identification
            "flow_id": f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}_{self.proto}",
            "timestamp": datetime.fromtimestamp(self.last_time, tz=timezone.utc).isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "service": service,
            "state": self.state,

            # UNSW-NB15 Standard Features
            "dur": round(dur, 6),
            "spkts": self.spkts,
            "dpkts": self.dpkts,
            "sbytes": self.sbytes,
            "dbytes": self.dbytes,
            "rate": round(rate, 4),
            "sttl": self.sttl,
            "dttl": self.dttl,
            "sload": round(sload, 4),
            "dload": round(dload, 4),
            "sloss": self.sloss,
            "dloss": self.dloss,
            "sinpkt": round(sinpkt * 1000.0, 4),  # ms
            "dinpkt": round(dinpkt * 1000.0, 4),  # ms
            "sjit": round(sjit * 1000.0, 4),
            "djit": round(djit * 1000.0, 4),
            "swin": self.swin,
            "stcpb": self.stcpb,
            "dtcpb": self.dtcpb,
            "dwin": self.dwin,
            "tcprtt": round(tcprtt * 1000.0, 4),
            "synack": round(synack * 1000.0, 4),
            "ackdat": round(ackdat * 1000.0, 4),
            "smean": round(smean, 2),
            "dmean": round(dmean, 2),
            "pkt_size_var": round(pkt_size_var, 2),

            # Flag Ratios
            "syn_ratio": round(syn_ratio, 4),
            "ack_ratio": round(ack_ratio, 4),
            "fin_ratio": round(fin_ratio, 4),
            "rst_ratio": round(rst_ratio, 4),

            # Window connection counters
            "ct_srv_src": c_stats.get("ct_srv_src", 1),
            "ct_state_ttl": c_stats.get("ct_state_ttl", 1),
            "ct_dst_ltm": c_stats.get("ct_dst_ltm", 1),
            "ct_src_dport_ltm": c_stats.get("ct_src_dport_ltm", 1),
            "ct_dst_sport_ltm": c_stats.get("ct_dst_sport_ltm", 1),
            "ct_dst_src_ltm": c_stats.get("ct_dst_src_ltm", 1),
        }
        return features


class FlowManager:
    """Manages active network flows, sliding window connection tables, and timeouts."""

    def __init__(self, flow_timeout: float = 15.0, active_timeout: float = 60.0):
        self.flow_timeout = flow_timeout
        self.active_timeout = active_timeout
        self.active_flows: Dict[Tuple[str, str, int, int, str], NetworkFlow] = {}

        # Sliding window connection tracker for UNSW-NB15 ct_* metrics
        self._history_records: List[Dict[str, Any]] = []
        self._history_window = 100

    def get_canonical_key(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str
    ) -> Tuple[Tuple[str, str, int, int, str], bool]:
        """Return canonical bi-directional key and whether packet is forward."""
        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        rev_key = (dst_ip, src_ip, dst_port, src_port, proto)

        if fwd_key in self.active_flows:
            return fwd_key, True
        if rev_key in self.active_flows:
            return rev_key, False
        return fwd_key, True

    def process_packet_meta(self, pkt: PacketMetadata) -> Optional[Dict[str, Any]]:
        """Add packet to appropriate flow and return completed flow if flushed."""
        key, is_forward = self.get_canonical_key(
            pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto
        )

        if key not in self.active_flows:
            self.active_flows[key] = NetworkFlow(key, pkt.timestamp)

        flow = self.active_flows[key]
        flow.add_packet(pkt)

        # Check if flow finished (e.g. FIN/RST or active timeout)
        flushed_features = None
        if flow.state in ("FIN", "RST") or (pkt.timestamp - flow.start_time) >= self.active_timeout:
            flushed_features = self.flush_flow(key)

        return flushed_features

    def flush_flow(self, key: Tuple[str, str, int, int, str]) -> Optional[Dict[str, Any]]:
        """Remove and return computed features for a flow."""
        flow = self.active_flows.pop(key, None)
        if not flow:
            return None

        # Compute connection context statistics
        c_stats = self._compute_context_stats(flow)
        features = flow.compute_features(c_stats)

        # Update sliding history
        self._history_records.append({
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "service": features["service"],
            "state": flow.state,
            "sttl": flow.sttl
        })
        if len(self._history_records) > self._history_window:
            self._history_records.pop(0)

        return features

    def flush_expired(self, current_time: float) -> List[Dict[str, Any]]:
        """Flush flows that have exceeded inactivity or active duration thresholds."""
        expired_keys = []
        for key, flow in self.active_flows.items():
            if (current_time - flow.last_time) >= self.flow_timeout or \
               (current_time - flow.start_time) >= self.active_timeout:
                expired_keys.append(key)

        flushed = []
        for key in expired_keys:
            feat = self.flush_flow(key)
            if feat:
                flushed.append(feat)
        return flushed

    def _compute_context_stats(self, flow: NetworkFlow) -> Dict[str, int]:
        """Calculate UNSW-NB15 ct_* contextual connection statistics."""
        ct_srv_src = 1
        ct_state_ttl = 1
        ct_dst_ltm = 1
        ct_src_dport_ltm = 1
        ct_dst_sport_ltm = 1
        ct_dst_src_ltm = 1

        for r in self._history_records:
            if r["src_ip"] == flow.src_ip and r["service"] == flow.compute_features().get("service"):
                ct_srv_src += 1
            if r["state"] == flow.state and r["sttl"] == flow.sttl:
                ct_state_ttl += 1
            if r["dst_ip"] == flow.dst_ip:
                ct_dst_ltm += 1
            if r["src_ip"] == flow.src_ip and r["dst_port"] == flow.dst_port:
                ct_src_dport_ltm += 1
            if r["dst_ip"] == flow.dst_ip and r["src_port"] == flow.src_port:
                ct_dst_sport_ltm += 1
            if r["src_ip"] == flow.src_ip and r["dst_ip"] == flow.dst_ip:
                ct_dst_src_ltm += 1

        return {
            "ct_srv_src": ct_srv_src,
            "ct_state_ttl": ct_state_ttl,
            "ct_dst_ltm": ct_dst_ltm,
            "ct_src_dport_ltm": ct_src_dport_ltm,
            "ct_dst_sport_ltm": ct_dst_sport_ltm,
            "ct_dst_src_ltm": ct_dst_src_ltm,
        }


class KafkaTelemetryProducer:
    """Asynchronous Kafka Producer with 10ms linger, batching, and resilience."""

    def __init__(
        self,
        bootstrap_servers: List[str],
        topic: str,
        linger_ms: int = 10,
        acks: int = 1,
        compression_type: str = "gzip"
    ):
        self.topic = topic
        self.producer = None
        self.in_memory_queue: List[Dict[str, Any]] = []

        if KAFKA_AVAILABLE:
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=bootstrap_servers,
                    linger_ms=linger_ms,
                    acks=acks,
                    compression_type=compression_type if compression_type in ("gzip", "snappy") else None,
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    key_serializer=lambda k: k.encode("utf-8") if k else None,
                    retries=3,
                    request_timeout_ms=5000,
                )
                logger.info(f"Kafka Producer connected to {bootstrap_servers}, streaming to topic: {topic}")
            except Exception as e:
                logger.warning(f"Could not connect Kafka Producer to {bootstrap_servers}: {e}. Operating in resilient fallback mode.")
                self.producer = None
        else:
            logger.info("Kafka library unavailable; using local in-memory streaming.")

    def send_telemetry(self, flow_data: Dict[str, Any]) -> None:
        """Asynchronously stream flow telemetry."""
        key = flow_data.get("src_ip", "")
        if self.producer:
            try:
                self.producer.send(self.topic, key=key, value=flow_data)
            except Exception as e:
                logger.error(f"Error publishing to Kafka: {e}")
                self.in_memory_queue.append(flow_data)
        else:
            self.in_memory_queue.append(flow_data)
            if len(self.in_memory_queue) > 10000:
                self.in_memory_queue.pop(0)

    def flush(self) -> None:
        """Flush buffered messages to broker."""
        if self.producer:
            try:
                self.producer.flush(timeout=2.0)
            except Exception as e:
                logger.warning(f"Error during producer flush: {e}")

    def close(self) -> None:
        """Close producer cleanly."""
        if self.producer:
            self.producer.close()


class FlowExtractor:
    """Orchestrates packet capture, flow aggregation, and telemetry emission."""

    def __init__(
        self,
        config_path: str = "config/config.yaml",
        telemetry_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.config = self._load_config(config_path)
        self.flow_manager = FlowManager(
            flow_timeout=float(self.config["sniffer"].get("flow_timeout", 15.0)),
            active_timeout=float(self.config["sniffer"].get("active_timeout", 60.0))
        )
        self.telemetry_callback = telemetry_callback

        kafka_cfg = self.config.get("kafka", {})
        self.producer = KafkaTelemetryProducer(
            bootstrap_servers=kafka_cfg.get("bootstrap_servers", ["localhost:9092"]),
            topic=kafka_cfg.get("telemetry_topic", "network-telemetry"),
            linger_ms=int(kafka_cfg.get("linger_ms", 10)),
            acks=int(kafka_cfg.get("acks", 1)),
            compression_type=kafka_cfg.get("compression_type", "gzip")
        )
        self.total_packets_seen = 0
        self.total_flows_emitted = 0

    @staticmethod
    def _load_config(path: str) -> Dict[str, Any]:
        return load_config(path)

    def handle_packet(self, pkt: Packet) -> None:
        """Scapy callback to extract metadata and update flow state."""
        self.total_packets_seen += 1
        meta = self._parse_scapy_packet(pkt)
        if not meta:
            return

        flow_data = self.flow_manager.process_packet_meta(meta)
        if flow_data:
            self._emit_flow(flow_data)

    def _emit_flow(self, flow_data: Dict[str, Any]) -> None:
        """Emit telemetry to Kafka and optional callback."""
        self.total_flows_emitted += 1
        self.producer.send_telemetry(flow_data)
        if self.telemetry_callback:
            self.telemetry_callback(flow_data)

    @staticmethod
    def _parse_scapy_packet(pkt: Packet) -> Optional[PacketMetadata]:
        """Convert Scapy packet to lightweight PacketMetadata."""
        if not SCAPY_AVAILABLE or not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        length = len(pkt)
        ttl = ip_layer.ttl
        proto_num = ip_layer.proto

        src_port = 0
        dst_port = 0
        tcp_flags: Dict[str, bool] = {}
        tcp_seq = 0
        tcp_ack = 0
        tcp_win = 0
        payload_len = 0

        if proto_num == 6 and pkt.haslayer(TCP):
            proto = "tcp"
            tcp_layer = pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = str(tcp_layer.flags)
            tcp_flags = {
                "SYN": "S" in flags,
                "ACK": "A" in flags,
                "FIN": "F" in flags,
                "RST": "R" in flags,
                "PSH": "P" in flags,
                "URG": "U" in flags,
            }
            tcp_seq = tcp_layer.seq
            tcp_ack = tcp_layer.ack
            tcp_win = tcp_layer.window
            payload_len = len(tcp_layer.payload)

        elif proto_num == 17 and pkt.haslayer(UDP):
            proto = "udp"
            udp_layer = pkt[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            payload_len = len(udp_layer.payload)

        elif proto_num == 1 and pkt.haslayer(ICMP):
            proto = "icmp"
        else:
            proto = f"proto-{proto_num}"

        return PacketMetadata(
            timestamp=float(pkt.time if hasattr(pkt, "time") else time.time()),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            length=length,
            ttl=ttl,
            tcp_flags=tcp_flags,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            tcp_window=tcp_win,
            payload_len=payload_len,
        )

    def generate_synthetic_flow(self, attack_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a realistic synthetic UNSW-NB15 flow for testing and benchmarking.
        Supports: Normal, DoS, Exploits, Fuzzers, Reconnaissance, Generic.
        """
        attack_cat = attack_type or random.choice(
            ["Normal", "Normal", "Normal", "DoS", "Exploits", "Fuzzers", "Reconnaissance", "Generic"]
        )

        now = time.time()
        is_attack = (attack_cat != "Normal")

        if attack_cat == "DoS":
            src_ip = f"192.168.1.{random.randint(10, 50)}"
            dst_ip = "10.0.0.5"
            src_port = random.randint(1024, 65535)
            dst_port = 80
            proto = "tcp"
            dur = random.uniform(0.001, 0.5)
            spkts = random.randint(500, 2500)
            dpkts = random.randint(0, 10)
            sbytes = spkts * random.randint(40, 64)
            dbytes = dpkts * 40
            syn_ratio = random.uniform(0.85, 1.0)
            ack_ratio = random.uniform(0.0, 0.05)
            fin_ratio = 0.0
            rst_ratio = random.uniform(0.0, 0.1)
            sttl = 64
            dttl = 0
            swin = 1024
            dwin = 0
        elif attack_cat == "Exploits":
            src_ip = f"172.16.5.{random.randint(2, 254)}"
            dst_ip = "10.0.0.12"
            src_port = random.randint(1024, 65535)
            dst_port = 443
            proto = "tcp"
            dur = random.uniform(0.5, 4.0)
            spkts = random.randint(30, 80)
            dpkts = random.randint(20, 60)
            sbytes = random.randint(8000, 45000)
            dbytes = random.randint(12000, 60000)
            syn_ratio = 0.05
            ack_ratio = 0.85
            fin_ratio = 0.05
            rst_ratio = 0.0
            sttl = 64
            dttl = 64
            swin = 29200
            dwin = 29200
        elif attack_cat == "Reconnaissance":
            src_ip = f"192.168.2.{random.randint(100, 200)}"
            dst_ip = f"10.0.0.{random.randint(1, 254)}"
            src_port = random.randint(30000, 60000)
            dst_port = random.choice([21, 22, 23, 25, 80, 443, 8080, 3389])
            proto = "tcp"
            dur = random.uniform(0.0001, 0.05)
            spkts = 2
            dpkts = 1
            sbytes = 120
            dbytes = 60
            syn_ratio = 0.5
            ack_ratio = 0.0
            fin_ratio = 0.0
            rst_ratio = 0.5
            sttl = 64
            dttl = 64
            swin = 1024
            dwin = 0
        else:  # Normal benign flow
            src_ip = f"10.0.1.{random.randint(1, 200)}"
            dst_ip = f"10.0.2.{random.randint(1, 200)}"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 53, 22])
            proto = "tcp" if dst_port != 53 else "udp"
            dur = random.uniform(0.01, 10.0)
            spkts = random.randint(5, 50)
            dpkts = random.randint(4, 45)
            sbytes = spkts * random.randint(60, 1200)
            dbytes = dpkts * random.randint(60, 1400)
            syn_ratio = 0.05
            ack_ratio = 0.90
            fin_ratio = 0.05
            rst_ratio = 0.0
            sttl = 64
            dttl = 64
            swin = 65535
            dwin = 65535

        total_pkts = spkts + dpkts
        rate = total_pkts / max(0.0001, dur)
        sload = (sbytes * 8.0) / max(0.0001, dur)
        dload = (dbytes * 8.0) / max(0.0001, dur)

        flow = {
            "flow_id": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}_{proto}",
            "timestamp": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "service": "http" if dst_port == 80 else ("ssl" if dst_port == 443 else "-"),
            "state": "CON" if is_attack is False else "REQ",
            "dur": round(dur, 6),
            "spkts": spkts,
            "dpkts": dpkts,
            "sbytes": sbytes,
            "dbytes": dbytes,
            "rate": round(rate, 4),
            "sttl": sttl,
            "dttl": dttl,
            "sload": round(sload, 4),
            "dload": round(dload, 4),
            "sloss": 0 if not is_attack else random.randint(1, 15),
            "dloss": 0,
            "sinpkt": round(random.uniform(0.1, 5.0), 4),
            "dinpkt": round(random.uniform(0.1, 5.0), 4),
            "sjit": round(random.uniform(0.01, 2.0), 4),
            "djit": round(random.uniform(0.01, 2.0), 4),
            "swin": swin,
            "stcpb": random.randint(100000, 999999),
            "dtcpb": random.randint(100000, 999999),
            "dwin": dwin,
            "tcprtt": round(random.uniform(0.5, 10.0), 4),
            "synack": round(random.uniform(0.2, 5.0), 4),
            "ackdat": round(random.uniform(0.2, 5.0), 4),
            "smean": round(sbytes / spkts, 2),
            "dmean": round(dbytes / max(1, dpkts), 2),
            "pkt_size_var": round(random.uniform(100.0, 50000.0), 2),
            "syn_ratio": round(syn_ratio, 4),
            "ack_ratio": round(ack_ratio, 4),
            "fin_ratio": round(fin_ratio, 4),
            "rst_ratio": round(rst_ratio, 4),
            "ct_srv_src": random.randint(1, 20),
            "ct_state_ttl": random.randint(1, 10),
            "ct_dst_ltm": random.randint(1, 15),
            "ct_src_dport_ltm": random.randint(1, 15),
            "ct_dst_sport_ltm": random.randint(1, 10),
            "ct_dst_src_ltm": random.randint(1, 15),
            # Metadata for evaluation / verification
            "_ground_truth": attack_cat,
        }
        return flow

    def run_simulation(self, count: int = 100, delay_ms: int = 10) -> None:
        """Run synthetic flow generator and stream to Kafka."""
        logger.info(f"Starting simulation: generating {count} synthetic UNSW-NB15 flows (delay={delay_ms}ms)...")
        for i in range(count):
            flow = self.generate_synthetic_flow()
            self._emit_flow(flow)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

        self.producer.flush()
        logger.info(f"Simulation completed. Total flows emitted: {self.total_flows_emitted}")

    def run_live(self) -> None:
        """Run live sniffing on specified interface."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is required for live capture. Please install scapy.")
            sys.exit(1)

        iface = self.config["sniffer"].get("interface")
        bpf_filter = self.config["sniffer"].get("bpf_filter", "ip")
        logger.info(f"Starting live AsyncSniffer on interface={iface or 'default'}, filter='{bpf_filter}'")

        sniffer = AsyncSniffer(
            iface=iface,
            filter=bpf_filter,
            prn=self.handle_packet,
            store=False
        )
        sniffer.start()

        try:
            while True:
                time.sleep(2.0)
                flushed = self.flow_manager.flush_expired(time.time())
                for f in flushed:
                    self._emit_flow(f)
                self.producer.flush()
        except KeyboardInterrupt:
            logger.info("Stopping sniffer...")
            sniffer.stop()
            self.producer.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSentinel Flow Extractor & Streamer")
    parser.add_argument("--mode", choices=["live", "simulation"], default="simulation", help="Execution mode")
    parser.add_argument("--count", type=int, default=50, help="Number of simulated flows")
    parser.add_argument("--delay-ms", type=int, default=10, help="Delay between flows in ms")
    parser.add_argument("--config", default="config/config.yaml", help="Path to config.yaml")
    args = parser.parse_args()

    extractor = FlowExtractor(config_path=args.config)
    if args.mode == "simulation":
        extractor.run_simulation(count=args.count, delay_ms=args.delay_ms)
    else:
        extractor.run_live()
