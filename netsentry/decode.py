"""Katman 2-7 paket cozucusu: Ethernet / IP / TCP / UDP / DNS / HTTP / TLS."""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

ETH_IPV4, ETH_IPV6, ETH_ARP, ETH_VLAN = 0x0800, 0x86DD, 0x0806, 0x8100
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE", 50: "ESP"}

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
             15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 65: "HTTPS"}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ",
                b"PATCH ", b"CONNECT ", b"TRACE ")


@dataclass
class Decoded:
    index: int
    timestamp: float
    length: int
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    tcp_flags: str = ""
    payload: bytes = b""
    dns: Optional[Dict[str, Any]] = None
    http: Optional[Dict[str, str]] = None
    tls_sni: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def flow_key(self) -> tuple:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)


# --------------------------------------------------------------------------- #
def decode(index: int, timestamp: float, data: bytes, link_type: int = 1,
           orig_len: int = 0) -> Optional[Decoded]:
    """Tek bir paketi cozer. orig_len verilirse (kirpilmis yakalamalarda)
    bayt istatistikleri icin gercek paket boyu kullanilir."""
    packet = Decoded(index=index, timestamp=timestamp, length=orig_len or len(data))
    payload, ethertype = _strip_link_layer(data, link_type)
    if payload is None:
        return None

    if ethertype == ETH_IPV4:
        rest = _decode_ipv4(payload, packet)
    elif ethertype == ETH_IPV6:
        rest = _decode_ipv6(payload, packet)
    elif ethertype == ETH_ARP:
        packet.protocol = "ARP"
        return packet
    else:
        return None
    if rest is None:
        return packet

    if packet.protocol == "TCP":
        rest = _decode_tcp(rest, packet)
    elif packet.protocol == "UDP":
        rest = _decode_udp(rest, packet)
    else:
        packet.payload = rest
        return packet

    if rest:
        packet.payload = rest
        _decode_application(packet, rest)
    return packet


def _strip_link_layer(data: bytes, link_type: int):
    if link_type == 1:  # Ethernet
        if len(data) < 14:
            return None, 0
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        while ethertype == ETH_VLAN and len(data) >= offset + 4:
            ethertype = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
        return data[offset:], ethertype
    if link_type == 101:  # RAW IP
        if not data:
            return None, 0
        version = data[0] >> 4
        return data, ETH_IPV4 if version == 4 else ETH_IPV6
    if link_type == 113:  # Linux cooked
        if len(data) < 16:
            return None, 0
        return data[16:], struct.unpack("!H", data[14:16])[0]
    if link_type == 0:  # NULL/loopback
        if len(data) < 4:
            return None, 0
        family = struct.unpack("<I", data[:4])[0]
        return data[4:], ETH_IPV4 if family == 2 else ETH_IPV6
    return None, 0


def _decode_ipv4(data: bytes, packet: Decoded) -> Optional[bytes]:
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    proto = data[9]
    packet.src_ip = socket.inet_ntoa(data[12:16])
    packet.dst_ip = socket.inet_ntoa(data[16:20])
    packet.protocol = PROTO_NAMES.get(proto, f"IP-{proto}")
    total_len = struct.unpack("!H", data[2:4])[0]
    end = total_len if 0 < total_len <= len(data) else len(data)
    return data[ihl:end]


def _decode_ipv6(data: bytes, packet: Decoded) -> Optional[bytes]:
    if len(data) < 40:
        return None
    next_header = data[6]
    packet.src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    packet.dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
    packet.protocol = PROTO_NAMES.get(next_header, f"IPv6-{next_header}")
    return data[40:]


_FLAG_BITS = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
              (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C")]


def _decode_tcp(data: bytes, packet: Decoded) -> bytes:
    if len(data) < 20:
        return b""
    packet.src_port, packet.dst_port = struct.unpack("!HH", data[:4])
    offset = ((data[12] >> 4) & 0x0F) * 4
    flags = data[13]
    packet.tcp_flags = "".join(ch for bit, ch in _FLAG_BITS if flags & bit) or "-"
    return data[offset:] if 20 <= offset <= len(data) else b""


def _decode_udp(data: bytes, packet: Decoded) -> bytes:
    if len(data) < 8:
        return b""
    packet.src_port, packet.dst_port, length, _ck = struct.unpack("!HHHH", data[:8])
    end = length if 8 <= length <= len(data) else len(data)
    return data[8:end]


# --------------------------------------------------------------------------- #
def _decode_application(packet: Decoded, payload: bytes) -> None:
    if packet.protocol == "UDP" and 53 in (packet.src_port, packet.dst_port):
        packet.dns = parse_dns(payload)
    elif packet.protocol == "TCP" and 53 in (packet.src_port, packet.dst_port):
        if len(payload) > 2:
            packet.dns = parse_dns(payload[2:])
    elif packet.protocol == "UDP" and 5353 in (packet.src_port, packet.dst_port):
        packet.dns = parse_dns(payload)
    if packet.protocol == "TCP":
        if payload.startswith(HTTP_METHODS):
            packet.http = parse_http_request(payload)
        elif payload[:5] == b"HTTP/":
            packet.http = {"type": "response",
                           "status": payload.split(b"\r\n", 1)[0].decode("latin-1")[:80]}
        sni = parse_tls_sni(payload)
        if sni:
            packet.tls_sni = sni


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple:
    """DNS adini (kompresyon destekli) okur. (isim, yeni_offset) doner."""
    labels: List[str] = []
    jumped = False
    original = offset
    while offset < len(data) and depth < 10:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original = offset + 2
                jumped = True
            if pointer >= len(data) or pointer == offset:
                break
            offset = pointer
            depth += 1
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("latin-1"))
        offset += length
    return ".".join(labels), (original if jumped else offset)


def parse_dns(payload: bytes) -> Optional[Dict[str, Any]]:
    if len(payload) < 12:
        return None
    try:
        txid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    except struct.error:
        return None
    result: Dict[str, Any] = {
        "id": txid,
        "is_response": bool(flags & 0x8000),
        "rcode": flags & 0x000F,
        "questions": [],
        "answers": [],
    }
    offset = 12
    for _ in range(min(qdcount, 8)):
        name, offset = _read_name(payload, offset)
        if offset + 4 > len(payload):
            break
        qtype, _qclass = struct.unpack("!HH", payload[offset:offset + 4])
        offset += 4
        result["questions"].append({"name": name, "type": DNS_TYPES.get(qtype, str(qtype))})
    for _ in range(min(ancount, 12)):
        if offset + 12 > len(payload):
            break
        name, offset = _read_name(payload, offset)
        if offset + 10 > len(payload):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", payload[offset:offset + 10])
        offset += 10
        rdata = payload[offset:offset + rdlen]
        offset += rdlen
        value = ""
        if rtype == 1 and len(rdata) == 4:
            value = socket.inet_ntoa(rdata)
        elif rtype == 28 and len(rdata) == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 16 and rdata:
            value = rdata[1:1 + rdata[0]].decode("latin-1")
        result["answers"].append({
            "name": name, "type": DNS_TYPES.get(rtype, str(rtype)),
            "value": value, "size": rdlen,
        })
    return result


def parse_http_request(payload: bytes) -> Dict[str, str]:
    text = payload[:8192].decode("latin-1")
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    request_line = lines[0].split(" ")
    out: Dict[str, str] = {
        "type": "request",
        "method": request_line[0] if request_line else "",
        "uri": request_line[1] if len(request_line) > 1 else "",
        "version": request_line[2] if len(request_line) > 2 else "",
    }
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key in ("host", "user-agent", "referer", "authorization",
                   "cookie", "content-type", "content-length"):
            out[key] = value.strip()
    return out


def parse_tls_sni(payload: bytes) -> str:
    """TLS ClientHello icinden Server Name Indication cikarir."""
    if len(payload) < 45 or payload[0] != 0x16 or payload[5] != 0x01:
        return ""
    try:
        pos = 43                      # record(5) + handshake(4) + version(2) + random(32)
        session_len = payload[pos]
        pos += 1 + session_len
        cipher_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return ""
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(payload))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            if ext_type == 0x0000 and pos + 5 <= len(payload):
                name_len = struct.unpack("!H", payload[pos + 3:pos + 5])[0]
                return payload[pos + 5:pos + 5 + name_len].decode("latin-1")
            pos += ext_len
    except (struct.error, IndexError, UnicodeDecodeError):
        return ""
    return ""
