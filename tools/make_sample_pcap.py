"""Sentetik ornek PCAP uretir (samples/ornek_trafik.pcap).

Icerik: normal web trafigi + C2 beacon + DNS tunelleme + port taramasi +
HTTP uzerinden exe indirme + sifresiz FTP + ICMP tuneli.
Tamami uydurma/laboratuvar verisidir, gercek bir yakalama degildir.
"""
from __future__ import annotations

import os
import random
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netsentry.pcap import write_pcap  # noqa: E402

random.seed(1337)

MAC_A = bytes.fromhex("001122334455")
MAC_B = bytes.fromhex("66778899aabb")


def eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return MAC_B + MAC_A + struct.pack("!H", ethertype) + payload


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload),
                         random.randint(0, 65535), 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"", seq: int = 1) -> bytes:
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags,
                         64240, 0, 0)
    return header + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    return header[:2] + struct.pack("!H", checksum(header + payload)) + header[4:] + payload


def dns_query(name: str, qtype: int = 1, txid: int | None = None) -> bytes:
    parts = b"".join(bytes([len(l)]) + l.encode() for l in name.split("."))
    return (struct.pack("!HHHHHH", txid or random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
            + parts + b"\x00" + struct.pack("!HH", qtype, 1))


def tls_client_hello(sni: str) -> bytes:
    host = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(host)) + host
    sni_ext_body = struct.pack("!H", len(server_name)) + server_name
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_body)) + sni_ext_body
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext
    body = (b"\x03\x03" + bytes(32) + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01"
            + b"\x01\x00" + extensions)
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


SYN, SA, ACK, PSH_ACK, RST = 0x02, 0x12, 0x10, 0x18, 0x04
packets: list = []
t = 1785000000.0   # 2026-07-25 civari


def add(ts: float, payload: bytes, orig_len: int = 0) -> None:
    """orig_len verilirse paket kirpilmis gibi yazilir (repo boyutunu kucuk tutar)."""
    frame = eth(payload)
    packets.append((ts, frame, orig_len) if orig_len else (ts, frame))


# --- 1) Normal web trafigi -------------------------------------------------
for i in range(12):
    ts = t + i * 3.7 + random.uniform(0, 1.5)
    add(ts, ipv4("10.0.0.15", "8.8.8.8", 17,
                 udp(50000 + i, 53, dns_query(random.choice(
                     ["www.python.org", "github.com", "cdn.jsdelivr.net",
                      "api.github.com", "docs.python.org"])))))
    add(ts + 0.05, ipv4("10.0.0.15", "140.82.121.4", 6, tcp(40000 + i, 443, SYN)))
    add(ts + 0.09, ipv4("140.82.121.4", "10.0.0.15", 6, tcp(443, 40000 + i, SA)))
    add(ts + 0.12, ipv4("10.0.0.15", "140.82.121.4", 6,
                        tcp(40000 + i, 443, PSH_ACK, tls_client_hello("github.com"))))
    add(ts + 0.30, ipv4("140.82.121.4", "10.0.0.15", 6,
                        tcp(443, 40000 + i, PSH_ACK, b"\x17\x03\x03" + bytes(1200))))

# --- 2) C2 beacon: her 60 saniyede bir, cok dusuk jitter -------------------
for i in range(14):
    ts = t + 20 + i * 60.0 + random.uniform(-0.6, 0.6)
    sport = 49500 + i
    add(ts, ipv4("10.0.0.23", "45.61.136.12", 6, tcp(sport, 443, SYN)))
    add(ts + 0.04, ipv4("45.61.136.12", "10.0.0.23", 6, tcp(443, sport, SA)))
    add(ts + 0.08, ipv4("10.0.0.23", "45.61.136.12", 6,
                        tcp(sport, 443, PSH_ACK, tls_client_hello("cdn-telemetry.top"))))
    add(ts + 0.20, ipv4("45.61.136.12", "10.0.0.23", 6,
                        tcp(443, sport, PSH_ACK, b"\x17\x03\x03" + bytes(180))))

# --- 3) DNS tunelleme ------------------------------------------------------
alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
for i in range(46):
    ts = t + 90 + i * 1.3
    label = "".join(random.choice(alphabet) for _ in range(48))
    qtype = 16 if i % 3 == 0 else 1     # bolumu TXT
    add(ts, ipv4("10.0.0.23", "8.8.8.8", 17,
                 udp(51000 + i, 53, dns_query(f"{label}.tun.datatransfer.xyz", qtype))))

# --- 4) DGA gorunumlu alan adlari ------------------------------------------
for i in range(8):
    ts = t + 140 + i * 2.0
    label = "".join(random.choice("bcdfghjklmnpqrstvwxz0123456789") for _ in range(16))
    add(ts, ipv4("10.0.0.23", "8.8.8.8", 17,
                 udp(52000 + i, 53, dns_query(f"{label}.com"))))

# --- 5) Port taramasi ------------------------------------------------------
scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
              1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
for i, port in enumerate(scan_ports):
    ts = t + 200 + i * 0.05
    add(ts, ipv4("10.0.0.99", "10.0.0.5", 6, tcp(60000 + i, port, SYN)))
    if port not in (22, 80, 443):
        add(ts + 0.01, ipv4("10.0.0.5", "10.0.0.99", 6, tcp(port, 60000 + i, RST)))

# --- 6) HTTP uzerinden exe indirme (curl UA) -------------------------------
http_req = (b"GET /payload/update.exe HTTP/1.1\r\n"
            b"Host: 194.87.144.9\r\n"
            b"User-Agent: curl/7.68.0\r\n"
            b"Accept: */*\r\n\r\n")
add(t + 210, ipv4("10.0.0.23", "194.87.144.9", 6, tcp(53001, 80, SYN)))
add(t + 210.05, ipv4("194.87.144.9", "10.0.0.23", 6, tcp(80, 53001, SA)))
add(t + 210.1, ipv4("10.0.0.23", "194.87.144.9", 6, tcp(53001, 80, PSH_ACK, http_req)))
for i in range(6):
    add(t + 210.2 + i * 0.1, ipv4("194.87.144.9", "10.0.0.23", 6,
                                  tcp(80, 53001, PSH_ACK, bytes(1400))))

# --- 7) Sifresiz HTTP Basic Auth -------------------------------------------
auth_req = (b"POST /admin/login HTTP/1.1\r\n"
            b"Host: intranet.sirket.local\r\n"
            b"User-Agent: python-requests/2.31.0\r\n"
            b"Authorization: Basic YWRtaW46UDRzc3cwcmQxMjM=\r\n"
            b"Content-Length: 0\r\n\r\n")
add(t + 215, ipv4("10.0.0.31", "10.0.0.7", 6, tcp(53100, 80, PSH_ACK, auth_req)))

# --- 8) Sifresiz FTP -------------------------------------------------------
add(t + 220, ipv4("10.0.0.31", "192.168.50.10", 6,
                  tcp(53200, 21, PSH_ACK, b"USER yedekleme\r\n")))
add(t + 220.5, ipv4("10.0.0.31", "192.168.50.10", 6,
                    tcp(53200, 21, PSH_ACK, b"PASS Yedek.2026!\r\n")))

# --- 9) Metasploit varsayilan portuna baglanti -----------------------------
add(t + 230, ipv4("10.0.0.23", "185.244.25.171", 6, tcp(53300, 4444, SYN)))
add(t + 230.1, ipv4("185.244.25.171", "10.0.0.23", 6, tcp(4444, 53300, SA)))

# --- 10) ICMP tuneli -------------------------------------------------------
for i in range(9):
    add(t + 240 + i * 1.1, ipv4("10.0.0.23", "45.61.136.12", 1,
                                icmp(bytes(random.getrandbits(8) for _ in range(420)))))

# --- 11) Veri sizdirma: buyuk giden transfer -------------------------------
# Buyuk transfer: paketler kirpilmis kaydedilir (orijinal boy baslikta korunur),
# boylece repo icindeki pcap kucuk kalirken bayt istatistikleri gercekci olur.
for i in range(900):
    add(t + 260 + i * 0.02,
        ipv4("10.0.0.31", "91.203.44.19", 6, tcp(53400, 8443, PSH_ACK, bytes(40))),
        orig_len=1454)
for i in range(20):
    add(t + 260 + i * 0.9, ipv4("91.203.44.19", "10.0.0.31", 6,
                                tcp(8443, 53400, ACK, bytes(60))))

packets.sort(key=lambda p: p[0])
out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "samples", "ornek_trafik.pcap")
os.makedirs(os.path.dirname(out), exist_ok=True)
write_pcap(out, iter(packets))
print(f"{len(packets)} paket yazildi -> {out}")
