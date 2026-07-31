"""Akis ve uygulama katmani verisinden supheli davranis cikaran dedektorler."""
from __future__ import annotations

import math
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .flows import Capture, Flow, is_private

SEVERITY_SCORE = {"low": 25, "medium": 50, "high": 75, "critical": 95}

# Sik kotuye kullanilan portlar
BAD_PORTS = {
    4444: "Metasploit varsayilan handler", 4445: "Metasploit alternatif",
    1337: "yaygin backdoor portu", 31337: "Back Orifice / elite backdoor",
    6667: "IRC (botnet C2)", 6697: "IRC over TLS", 5555: "ADB / bazi RAT'lar",
    9001: "Tor OR portu", 9050: "Tor SOCKS", 3333: "kripto madenci havuzu",
    14444: "kripto madenci havuzu", 45560: "yaygin RAT portu",
    8888: "alternatif proxy / madenci", 1080: "SOCKS proxy",
    23: "Telnet (sifresiz)", 2323: "Telnet (IoT botnet)",
}

SUSPICIOUS_TLDS = (".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".click",
                   ".zip", ".mov", ".icu", ".cyou", ".duckdns.org", ".ngrok.io",
                   ".sbs", ".buzz", ".rest")

RISKY_UA = re.compile(
    r"(?i)(python-requests|curl/|wget|powershell|winhttp|libwww|go-http-client|"
    r"java/|nikto|sqlmap|masscan|nmap|empire|cobaltstrike|axios/|okhttp)")

EXECUTABLE_URI = re.compile(r"(?i)\.(exe|dll|scr|ps1|bat|hta|jar|msi|vbs|bin|elf)(\?|$)")


@dataclass
class Finding:
    code: str
    title: str
    severity: str
    detail: str
    evidence: List[str] = field(default_factory=list)
    entities: Dict[str, Any] = field(default_factory=dict)

    @property
    def score(self) -> int:
        return SEVERITY_SCORE.get(self.severity, 50)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code, "title": self.title, "severity": self.severity,
            "score": self.score, "detail": self.detail,
            "evidence": self.evidence, "entities": self.entities,
        }


# --------------------------------------------------------------------------- #
def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = defaultdict(int)
    for char in text:
        counts[char] += 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def registered_domain(name: str) -> str:
    parts = name.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    two_level = {"co.uk", "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr", "co.jp"}
    if ".".join(parts[-2:]) in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _fmt_bytes(value: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f}{unit}" if unit != "B" else f"{value}B"
        value /= 1024.0
    return f"{value}"


# --------------------------------------------------------------------------- #
def detect_beaconing(capture: Capture, min_events: int = 6,
                     max_jitter: float = 0.15,
                     min_interval: float = 5.0) -> List[Finding]:
    """Duzenli araliklarla tekrarlanan baglantilar = olasi C2 beacon.

    Jitter = araliklarin standart sapmasi / ortalamasi. Insan ve normal uygulama
    trafigi duzensizdir; makine uretimi C2 beacon'lari ise cok dusuk jitter uretir.
    DNS (53) gibi dogasi geregi periyodik protokoller haric tutulur.
    """
    findings: List[Finding] = []
    for flow in capture.flows.values():
        times = sorted(flow.start_times)
        if len(times) < min_events or is_private(flow.dst_ip):
            continue
        if flow.dst_port in (53, 123, 5353, 67, 68):   # DNS / NTP / mDNS / DHCP
            continue
        intervals = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
        if len(intervals) < min_events - 1:
            continue
        mean = statistics.fmean(intervals)
        if mean < min_interval:
            continue
        stdev = statistics.pstdev(intervals)
        jitter = stdev / mean
        if jitter > max_jitter:
            continue
        severity = "critical" if jitter < 0.08 else "high"
        target = flow.sni or (flow.http_hosts[0] if flow.http_hosts else flow.dst_ip)
        findings.append(Finding(
            code="NS-BEACON",
            title="Duzenli aralikli baglanti (olasi C2 beacon)",
            severity=severity,
            detail=(f"{flow.src_ip} adresi {target}:{flow.dst_port} hedefine "
                    f"{len(times)} kez, ortalama {mean:.1f} saniye araliklarla baglandi "
                    f"(jitter %{jitter * 100:.1f})."),
            evidence=[f"aralik ornekleri: " +
                      ", ".join(f"{i:.1f}s" for i in intervals[:8]),
                      f"toplam veri: {_fmt_bytes(flow.total_bytes)}"],
            entities={"src_ip": flow.src_ip, "dst_ip": flow.dst_ip,
                      "dst_port": flow.dst_port, "domain": flow.sni,
                      "interval_sec": round(mean, 2), "jitter": round(jitter, 3)},
        ))
    return findings


def detect_dns_tunneling(capture: Capture) -> List[Finding]:
    """Uzun/rastgele alt alan adlari ve asiri sorgu hacmi = DNS tuneli."""
    findings: List[Finding] = []
    per_domain: Dict[str, List[dict]] = defaultdict(list)
    for query in capture.dns_queries:
        per_domain[registered_domain(query["name"])].append(query)

    for domain, queries in per_domain.items():
        if not domain or len(queries) < 5:
            continue
        subdomains = {q["name"] for q in queries}
        labels = [q["name"].split(".")[0] for q in queries if "." in q["name"]]
        if not labels:
            continue
        avg_label_len = statistics.fmean(len(x) for x in labels)
        avg_entropy = statistics.fmean(shannon_entropy(x) for x in labels)
        rare_types = sum(1 for q in queries if q["type"] in ("TXT", "NULL", "CNAME"))
        unique_ratio = len(subdomains) / len(queries)

        score = 0
        reasons = []
        if avg_label_len > 25:
            score += 2
            reasons.append(f"ortalama alt alan uzunlugu {avg_label_len:.0f} karakter")
        if avg_entropy > 3.6:
            score += 2
            reasons.append(f"yuksek entropi ({avg_entropy:.2f} bit/karakter)")
        if unique_ratio > 0.9 and len(queries) >= 10:
            score += 2
            reasons.append(f"{len(subdomains)} farkli alt alan adi / {len(queries)} sorgu")
        if rare_types >= max(3, len(queries) * 0.3):
            score += 1
            reasons.append(f"{rare_types} adet TXT/NULL sorgusu")
        if len(queries) > 50:
            score += 1
            reasons.append(f"toplam {len(queries)} sorgu")

        if score >= 4:
            findings.append(Finding(
                code="NS-DNSTUN",
                title="DNS tunelleme / DNS uzerinden veri sizdirma",
                severity="critical" if score >= 6 else "high",
                detail=(f"'{domain}' alan adina yapilan sorgular veri tasima "
                        f"deseni gosteriyor: " + "; ".join(reasons) + "."),
                evidence=[q["name"][:120] for q in queries[:5]],
                entities={"domain": domain, "query_count": len(queries),
                          "unique_subdomains": len(subdomains),
                          "avg_entropy": round(avg_entropy, 2),
                          "src_ips": sorted({q["src_ip"] for q in queries})},
            ))
    return findings


def detect_dga(capture: Capture) -> List[Finding]:
    """Algoritma uretimi gibi gorunen alan adlari."""
    suspects = []
    for query in capture.dns_queries:
        domain = registered_domain(query["name"])
        label = domain.split(".")[0]
        if len(label) < 10 or not re.fullmatch(r"[a-z0-9-]+", label):
            continue
        entropy = shannon_entropy(label)
        vowels = sum(1 for c in label if c in "aeiou") / len(label)
        digits = sum(1 for c in label if c.isdigit()) / len(label)
        if entropy > 3.4 and (vowels < 0.25 or digits > 0.3):
            suspects.append((domain, round(entropy, 2)))
    unique = sorted(set(suspects))
    if len(unique) < 3:
        return []
    return [Finding(
        code="NS-DGA",
        title="Algoritma uretimi (DGA) gorunumlu alan adlari",
        severity="high" if len(unique) >= 6 else "medium",
        detail=(f"{len(unique)} adet rastgele gorunumlu alan adi sorgulandi. "
                "Botnet C2 alan adi uretimi tipik gostergesidir."),
        evidence=[f"{d} (entropi {e})" for d, e in unique[:10]],
        entities={"domains": [d for d, _ in unique]},
    )]


def detect_port_scan(capture: Capture, port_threshold: int = 15,
                     host_threshold: int = 15) -> List[Finding]:
    findings: List[Finding] = []
    ports_by_src: Dict[str, set] = defaultdict(set)
    hosts_by_src: Dict[str, set] = defaultdict(set)
    for flow in capture.flows.values():
        if flow.syn_count and flow.packets <= 3:
            ports_by_src[flow.src_ip].add((flow.dst_ip, flow.dst_port))
            hosts_by_src[flow.src_ip].add(flow.dst_ip)

    for src, pairs in ports_by_src.items():
        ports = {p for _h, p in pairs}
        hosts = hosts_by_src[src]
        if len(ports) >= port_threshold and len(hosts) <= 3:
            findings.append(Finding(
                code="NS-PORTSCAN", title="Port taramasi",
                severity="high",
                detail=(f"{src} adresi {len(hosts)} hedefte {len(ports)} farkli porta "
                        "yanitsiz SYN gonderdi."),
                evidence=[f"portlar: " + ", ".join(str(p) for p in sorted(ports)[:25])],
                entities={"src_ip": src, "port_count": len(ports),
                          "targets": sorted(hosts)},
            ))
        elif len(hosts) >= host_threshold:
            findings.append(Finding(
                code="NS-SWEEP", title="Ag tarama (host sweep)",
                severity="high",
                detail=f"{src} adresi {len(hosts)} farkli hedefe baglanti denedi.",
                evidence=["hedefler: " + ", ".join(sorted(hosts)[:20])],
                entities={"src_ip": src, "host_count": len(hosts)},
            ))
    return findings


def detect_exfiltration(capture: Capture, threshold: int = 1024 * 1024,
                        ratio: float = 5.0) -> List[Finding]:
    """Disari dogru asiri veri transferi.

    threshold: tek bir harici hedefe giden minimum bayt (varsayilan 1 MB).
    ratio    : giden/gelen orani. Normal web trafiginde bu oran <1'dir;
               sizdirmada giden veri gelenin katlaridir.
    """
    findings: List[Finding] = []
    per_target: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"out": 0, "in": 0, "srcs": set(), "ports": set()})
    for flow in capture.flows.values():
        if is_private(flow.dst_ip):
            continue
        entry = per_target[flow.dst_ip]
        entry["out"] += flow.bytes_out
        entry["in"] += flow.bytes_in
        entry["srcs"].add(flow.src_ip)
        entry["ports"].add(flow.dst_port)

    for dst, entry in per_target.items():
        out_bytes, in_bytes = entry["out"], entry["in"]
        if out_bytes < threshold:
            continue
        if in_bytes and out_bytes / max(in_bytes, 1) < ratio:
            continue
        findings.append(Finding(
            code="NS-EXFIL", title="Buyuk hacimli giden veri transferi",
            severity="critical" if out_bytes > 20 * 1024 * 1024 else "high",
            detail=(f"{dst} hedefine {_fmt_bytes(out_bytes)} veri gonderildi, "
                    f"karsiliginda sadece {_fmt_bytes(in_bytes)} alindi."),
            evidence=[f"kaynak: {', '.join(sorted(entry['srcs']))}",
                      f"portlar: {', '.join(str(p) for p in sorted(entry['ports']))}"],
            entities={"dst_ip": dst, "bytes_out": out_bytes, "bytes_in": in_bytes},
        ))
    return findings


def detect_suspicious_ports(capture: Capture) -> List[Finding]:
    findings: List[Finding] = []
    seen: Dict[int, List[Flow]] = defaultdict(list)
    for flow in capture.flows.values():
        if flow.dst_port in BAD_PORTS and not is_private(flow.dst_ip):
            seen[flow.dst_port].append(flow)
    for port, flows in seen.items():
        findings.append(Finding(
            code="NS-BADPORT", title=f"Supheli hedef port {port}",
            severity="high" if port in (4444, 4445, 1337, 31337) else "medium",
            detail=f"{BAD_PORTS[port]} olarak bilinen {port} portuna baglanti tespit edildi.",
            evidence=[f.label for f in flows[:6]],
            entities={"port": port, "flows": [f.label for f in flows[:20]]},
        ))
    return findings


def detect_cleartext_secrets(capture: Capture) -> List[Finding]:
    """Sifresiz protokollerde tasinan kimlik bilgileri."""
    findings: List[Finding] = []
    for request in capture.http_requests:
        if request.get("authorization"):
            findings.append(Finding(
                code="NS-CLEARAUTH", title="Sifresiz HTTP uzerinde kimlik bilgisi",
                severity="high",
                detail=(f"{request['src_ip']} -> {request.get('host', request['dst_ip'])} "
                        "isteginde Authorization basligi duz metin tasiniyor."),
                evidence=[f"{request.get('method')} {request.get('uri', '')[:120]}",
                          f"Authorization: {request['authorization'][:40]}..."],
                entities={"src_ip": request["src_ip"], "dst_ip": request["dst_ip"]},
            ))
    ftp_hits, telnet_hits = [], []
    for packet in capture.packets:
        if packet.protocol != "TCP" or not packet.payload:
            continue
        if packet.dst_port == 21 and re.match(rb"(?i)^(USER|PASS)\s", packet.payload):
            ftp_hits.append(f"{packet.src_ip} -> {packet.dst_ip}: "
                            f"{packet.payload[:40].decode('latin-1').strip()}")
        elif packet.dst_port in (23, 2323) and len(packet.payload) > 1:
            telnet_hits.append(f"{packet.src_ip} -> {packet.dst_ip}:{packet.dst_port}")
    if ftp_hits:
        findings.append(Finding(
            code="NS-FTPCLEAR", title="Sifresiz FTP kimlik dogrulamasi",
            severity="medium", detail="FTP USER/PASS komutlari ag uzerinde duz metin gitti.",
            evidence=ftp_hits[:6], entities={"count": len(ftp_hits)}))
    if telnet_hits:
        findings.append(Finding(
            code="NS-TELNET", title="Telnet kullanimi",
            severity="medium",
            detail="Telnet trafigi tespit edildi; tum oturum sifresiz tasinir.",
            evidence=sorted(set(telnet_hits))[:6], entities={"count": len(telnet_hits)}))
    return findings


def detect_http_anomalies(capture: Capture) -> List[Finding]:
    findings: List[Finding] = []
    ua_hits, exe_hits, sus_host = [], [], []
    for request in capture.http_requests:
        agent = request.get("user-agent", "")
        host = request.get("host", request["dst_ip"])
        uri = request.get("uri", "")
        if agent and RISKY_UA.search(agent):
            ua_hits.append(f"{request['src_ip']} -> {host}  UA: {agent[:60]}")
        elif not agent:
            ua_hits.append(f"{request['src_ip']} -> {host}  (User-Agent yok)")
        if EXECUTABLE_URI.search(uri):
            exe_hits.append(f"{request['src_ip']} -> http://{host}{uri[:90]}")
        if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
            sus_host.append(f"{request['src_ip']} -> {host}")

    for entry in capture.tls_names:
        if any(entry["sni"].endswith(t) for t in SUSPICIOUS_TLDS):
            sus_host.append(f"{entry['src_ip']} -> {entry['sni']} (TLS SNI)")

    if ua_hits:
        findings.append(Finding(
            code="NS-BADUA", title="Otomatik arac / eksik User-Agent",
            severity="medium",
            detail="Tarayici disi istemcilerden HTTP istekleri gorulduG.".replace("G", ""),
            evidence=sorted(set(ua_hits))[:8], entities={"count": len(ua_hits)}))
    if exe_hits:
        findings.append(Finding(
            code="NS-EXEDL", title="Sifresiz HTTP uzerinden calistirilabilir dosya indirme",
            severity="high",
            detail="HTTP uzerinden .exe/.dll/.ps1 gibi bir dosya talep edildi.",
            evidence=sorted(set(exe_hits))[:8], entities={"count": len(exe_hits)}))
    if sus_host:
        findings.append(Finding(
            code="NS-BADTLD", title="Riskli ust seviye alan adina baglanti",
            severity="medium",
            detail="Kotuye kullanimi yaygin TLD'lere trafik tespit edildi.",
            evidence=sorted(set(sus_host))[:8], entities={"count": len(sus_host)}))
    return findings


def detect_icmp_tunnel(capture: Capture) -> List[Finding]:
    large = [p for p in capture.packets
             if p.protocol == "ICMP" and len(p.payload) > 128]
    if len(large) < 5:
        return []
    total = sum(len(p.payload) for p in large)
    return [Finding(
        code="NS-ICMPTUN", title="Buyuk ICMP yukleri (olasi ICMP tuneli)",
        severity="high",
        detail=(f"{len(large)} adet ICMP paketi 128 baytin uzerinde veri tasiyor "
                f"(toplam {_fmt_bytes(total)}). Normal ping paketleri 32-64 bayttir."),
        evidence=[f"{p.src_ip} -> {p.dst_ip}  {len(p.payload)} bayt" for p in large[:6]],
        entities={"packet_count": len(large), "total_bytes": total},
    )]


DETECTORS = (
    detect_beaconing, detect_dns_tunneling, detect_dga, detect_port_scan,
    detect_exfiltration, detect_suspicious_ports, detect_cleartext_secrets,
    detect_http_anomalies, detect_icmp_tunnel,
)


def run_all(capture: Capture) -> List[Finding]:
    findings: List[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(capture))
    findings.sort(key=lambda f: -f.score)
    return findings
