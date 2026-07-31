"""Saf standart kutuphane ile PCAP ve PCAPNG okuyucu."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Tuple

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
PCAPNG_SHB = 0x0A0D0D0A


class PcapError(ValueError):
    """Okunamayan / bozuk yakalama dosyasi."""


@dataclass
class Packet:
    index: int
    timestamp: float
    data: bytes
    link_type: int
    orig_len: int


def _read_classic(raw: bytes) -> Iterator[Packet]:
    magic = struct.unpack("<I", raw[:4])[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian, nano = "<", magic == PCAP_MAGIC_NS_LE
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        endian, nano = ">", magic == PCAP_MAGIC_NS_BE
    else:
        raise PcapError(f"bilinmeyen pcap magic: 0x{magic:08x}")

    link_type = struct.unpack(endian + "I", raw[20:24])[0]
    offset, index = 24, 0
    divisor = 1_000_000_000.0 if nano else 1_000_000.0
    while offset + 16 <= len(raw):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            endian + "IIII", raw[offset:offset + 16])
        offset += 16
        if incl_len > len(raw) - offset:
            break
        yield Packet(index, ts_sec + ts_frac / divisor,
                     raw[offset:offset + incl_len], link_type, orig_len)
        offset += incl_len
        index += 1


def _read_pcapng(raw: bytes) -> Iterator[Packet]:
    offset, index = 0, 0
    endian = "<"
    link_types = []
    tsresol = [6]
    while offset + 12 <= len(raw):
        block_type = struct.unpack(endian + "I", raw[offset:offset + 4])[0]
        if block_type == PCAPNG_SHB:
            byte_order = struct.unpack("<I", raw[offset + 8:offset + 12])[0]
            endian = "<" if byte_order == 0x1A2B3C4D else ">"
            block_type = struct.unpack(endian + "I", raw[offset:offset + 4])[0]
        block_len = struct.unpack(endian + "I", raw[offset + 4:offset + 8])[0]
        if block_len < 12 or offset + block_len > len(raw):
            break
        body = raw[offset + 8:offset + block_len - 4]

        if block_type == 0x00000001:  # Interface Description Block
            link_types.append(struct.unpack(endian + "H", body[0:2])[0])
            tsresol.append(_parse_tsresol(body[8:], endian))
        elif block_type == 0x00000006:  # Enhanced Packet Block
            iface, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                endian + "IIIII", body[:20])
            resol = tsresol[iface + 1] if iface + 1 < len(tsresol) else 6
            ticks = (ts_high << 32) | ts_low
            yield Packet(index, ticks / (10 ** resol), body[20:20 + cap_len],
                         link_types[iface] if iface < len(link_types) else 1, orig_len)
            index += 1
        elif block_type == 0x00000003:  # Simple Packet Block
            orig_len = struct.unpack(endian + "I", body[:4])[0]
            yield Packet(index, 0.0, body[4:4 + orig_len],
                         link_types[0] if link_types else 1, orig_len)
            index += 1
        offset += block_len
    return


def _parse_tsresol(options: bytes, endian: str) -> int:
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[pos:pos + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            value = options[pos + 4]
            return value & 0x7F if not value & 0x80 else 6
        pos += 4 + ((length + 3) // 4) * 4
    return 6


def read_packets(path: str) -> Iterator[Packet]:
    """PCAP veya PCAPNG dosyasindan paketleri sirayla dondurur."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if len(raw) < 24:
        raise PcapError("dosya cok kucuk veya bos")
    first = struct.unpack(">I", raw[:4])[0]
    if first == PCAPNG_SHB:
        yield from _read_pcapng(raw)
    else:
        yield from _read_classic(raw)


def write_pcap(path: str, packets, link_type: int = 1, snaplen: int = 0) -> None:
    """Test/ornek uretimi icin basit pcap yazici.

    packets: (timestamp, data) veya (timestamp, data, orijinal_uzunluk) demetleri.
    snaplen > 0 verilirse paketler kirpilarak yazilir (tcpdump -s davranisi);
    orijinal uzunluk baslikta korunur, boylece bayt istatistikleri dogru kalir.
    """
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_LE, 2, 4, 0, 0,
                             snaplen or 65535, link_type))
        for item in packets:
            ts, data = item[0], item[1]
            orig_len = item[2] if len(item) > 2 else len(data)
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            stored = data[:snaplen] if snaplen else data
            fh.write(struct.pack("<IIII", sec, usec, len(stored),
                                 max(orig_len, len(stored))))
            fh.write(stored)
