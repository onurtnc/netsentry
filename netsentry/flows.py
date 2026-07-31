"""Paketleri akislara (flow) toplar ve ozet istatistik uretir."""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple

from .decode import Decoded


def is_private(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (address.is_private or address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_reserved)


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    packets: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    start_times: List[float] = field(default_factory=list)
    syn_count: int = 0
    sni: str = ""
    http_hosts: List[str] = field(default_factory=list)

    @property
    def key(self) -> Tuple[str, str, int, str]:
        return (self.src_ip, self.dst_ip, self.dst_port, self.protocol)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def total_bytes(self) -> int:
        return self.bytes_out + self.bytes_in

    @property
    def label(self) -> str:
        return f"{self.src_ip} -> {self.dst_ip}:{self.dst_port}/{self.protocol}"

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip, "dst_ip": self.dst_ip, "dst_port": self.dst_port,
            "protocol": self.protocol, "packets": self.packets,
            "bytes_out": self.bytes_out, "bytes_in": self.bytes_in,
            "duration_sec": round(self.duration, 3),
            "connections": len(self.start_times),
            "sni": self.sni, "http_hosts": sorted(set(self.http_hosts))[:5],
        }


@dataclass
class Capture:
    flows: Dict[Tuple[str, str, int, str], Flow] = field(default_factory=dict)
    packets: List[Decoded] = field(default_factory=list)
    dns_queries: List[dict] = field(default_factory=list)
    http_requests: List[dict] = field(default_factory=list)
    tls_names: List[dict] = field(default_factory=list)
    total_packets: int = 0
    total_bytes: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    @property
    def talkers(self) -> List[Tuple[str, int]]:
        totals: Dict[str, int] = defaultdict(int)
        for flow in self.flows.values():
            totals[flow.src_ip] += flow.total_bytes
        return sorted(totals.items(), key=lambda kv: -kv[1])

    @property
    def external_flows(self) -> List[Flow]:
        return [f for f in self.flows.values() if not is_private(f.dst_ip)]


def build_capture(packets: Iterable[Decoded]) -> Capture:
    capture = Capture()
    for packet in packets:
        if packet is None:
            continue
        capture.total_packets += 1
        capture.total_bytes += packet.length
        if capture.start_time == 0.0 or packet.timestamp < capture.start_time:
            capture.start_time = packet.timestamp
        capture.end_time = max(capture.end_time, packet.timestamp)
        capture.packets.append(packet)

        if packet.dns and not packet.dns["is_response"]:
            for question in packet.dns["questions"]:
                capture.dns_queries.append({
                    "timestamp": packet.timestamp, "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip, "name": question["name"],
                    "type": question["type"], "size": packet.length,
                })
        if packet.http and packet.http.get("type") == "request":
            capture.http_requests.append({
                "timestamp": packet.timestamp, "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip, "port": packet.dst_port, **packet.http,
            })
        if packet.tls_sni:
            capture.tls_names.append({
                "timestamp": packet.timestamp, "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip, "sni": packet.tls_sni,
            })

        if not packet.src_ip or packet.protocol in ("ARP",):
            continue

        forward = (packet.src_ip, packet.dst_ip, packet.dst_port, packet.protocol)
        reverse = (packet.dst_ip, packet.src_ip, packet.src_port, packet.protocol)
        if reverse in capture.flows:
            flow = capture.flows[reverse]
            flow.bytes_in += packet.length
        else:
            flow = capture.flows.get(forward)
            if flow is None:
                flow = Flow(packet.src_ip, packet.dst_ip, packet.dst_port,
                            packet.protocol, first_seen=packet.timestamp)
                capture.flows[forward] = flow
            flow.bytes_out += packet.length
        flow.packets += 1
        flow.last_seen = max(flow.last_seen, packet.timestamp)
        if "S" in packet.tcp_flags and "A" not in packet.tcp_flags:
            flow.syn_count += 1
            flow.start_times.append(packet.timestamp)
        elif packet.protocol == "UDP":
            flow.start_times.append(packet.timestamp)
        if packet.tls_sni:
            flow.sni = packet.tls_sni
        if packet.http and packet.http.get("host"):
            flow.http_hosts.append(packet.http["host"])
    return capture
