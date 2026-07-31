"""NetSentry ciktilari: konsol, JSON, HTML."""
from __future__ import annotations

import datetime as dt
import html
import json
from typing import List

from .detect import Finding
from .flows import Capture, is_private

COLORS = {"critical": "\033[97;41m", "high": "\033[91m",
          "medium": "\033[93m", "low": "\033[96m"}
HEX = {"critical": "#b3001b", "high": "#e8590c", "medium": "#f08c00", "low": "#1c7ed6"}
RESET, BOLD = "\033[0m", "\033[1m"


def _c(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{RESET}" if use_color else text


def fmt_bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def _stamp(value: float) -> str:
    if not value:
        return "-"
    return dt.datetime.utcfromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


def risk_score(findings: List[Finding]) -> int:
    if not findings:
        return 0
    return min(100, max(f.score for f in findings) + min(10, len(findings)))


def to_console(capture: Capture, findings: List[Finding],
               use_color: bool = True, top: int = 10) -> str:
    lines: List[str] = []
    lines.append(_c("=" * 78, BOLD, use_color))
    lines.append(_c("  NetSentry - Ag Trafigi Analiz Raporu", BOLD, use_color))
    lines.append(_c("=" * 78, BOLD, use_color))
    lines.append(f"  Paket    : {capture.total_packets}   "
                 f"Veri: {fmt_bytes(capture.total_bytes)}   "
                 f"Akis: {len(capture.flows)}")
    lines.append(f"  Zaman    : {_stamp(capture.start_time)} - {_stamp(capture.end_time)} "
                 f"({capture.duration:.1f} sn)")
    lines.append(f"  DNS      : {len(capture.dns_queries)} sorgu   "
                 f"HTTP: {len(capture.http_requests)} istek   "
                 f"TLS: {len(capture.tls_names)} SNI")
    score = risk_score(findings)
    bar = "#" * (score // 5) + "." * (20 - score // 5)
    lines.append(f"  Risk     : [{bar}] {score}/100   Bulgu: {len(findings)}")
    lines.append("-" * 78)

    if findings:
        for finding in findings:
            lines.append(_c(f"[{finding.severity.upper()}] {finding.title}",
                            COLORS.get(finding.severity, ""), use_color))
            lines.append(f"    {finding.detail}")
            for item in finding.evidence[:6]:
                lines.append(f"      - {item}")
            lines.append("")
    else:
        lines.append("  Supheli bir davranis tespit edilmedi.\n")

    talkers = capture.talkers[:top]
    if talkers:
        lines.append(_c("  EN COK KONUSAN KAYNAKLAR", BOLD, use_color))
        for ip, total in talkers:
            tag = "" if is_private(ip) else "  (harici)"
            lines.append(f"    {ip:<40} {fmt_bytes(total):>12}{tag}")
        lines.append("")

    external = sorted(capture.external_flows, key=lambda f: -f.total_bytes)[:top]
    if external:
        lines.append(_c("  EN BUYUK HARICI AKISLAR", BOLD, use_color))
        for flow in external:
            name = flow.sni or (flow.http_hosts[0] if flow.http_hosts else "")
            suffix = f"  [{name}]" if name else ""
            lines.append(f"    {flow.label:<52} {fmt_bytes(flow.total_bytes):>10}"
                         f"  {flow.packets} pkt{suffix}")
        lines.append("")
    return "\n".join(lines)


def to_json(capture: Capture, findings: List[Finding]) -> str:
    return json.dumps({
        "summary": {
            "packets": capture.total_packets,
            "bytes": capture.total_bytes,
            "flows": len(capture.flows),
            "duration_sec": round(capture.duration, 3),
            "start": _stamp(capture.start_time),
            "end": _stamp(capture.end_time),
            "dns_queries": len(capture.dns_queries),
            "http_requests": len(capture.http_requests),
            "risk_score": risk_score(findings),
            "finding_count": len(findings),
        },
        "findings": [f.to_dict() for f in findings],
        "top_talkers": [{"ip": ip, "bytes": b} for ip, b in capture.talkers[:20]],
        "external_flows": [f.to_dict() for f in
                           sorted(capture.external_flows,
                                  key=lambda x: -x.total_bytes)[:50]],
        "dns_queries": capture.dns_queries[:200],
    }, indent=2, ensure_ascii=False)


def to_html(capture: Capture, findings: List[Finding]) -> str:
    score = risk_score(findings)
    cards = "".join(
        f"<div class='card'><b>{v}</b><span>{k}</span></div>" for k, v in [
            ("paket", capture.total_packets), ("akis", len(capture.flows)),
            ("veri", fmt_bytes(capture.total_bytes)),
            ("DNS sorgu", len(capture.dns_queries)),
            ("HTTP istek", len(capture.http_requests)),
            ("bulgu", len(findings)), ("risk", f"{score}/100")])

    rows = "".join(
        f"""<tr><td class='lvl'><span style="background:{HEX.get(f.severity, '#868e96')}">
        {html.escape(f.severity.upper())}</span></td>
        <td><div class='title'>{html.escape(f.title)}</div>
        <div class='d'>{html.escape(f.detail)}</div>
        <ul>{''.join(f'<li><code>{html.escape(str(e))}</code></li>' for e in f.evidence[:8])}</ul>
        </td><td class='score'>{f.score}</td></tr>"""
        for f in findings) or "<tr><td colspan=3>Supheli davranis tespit edilmedi.</td></tr>"

    talkers = "".join(
        f"<tr><td><code>{html.escape(ip)}</code></td><td>{fmt_bytes(b)}</td>"
        f"<td>{'ic ag' if is_private(ip) else 'harici'}</td></tr>"
        for ip, b in capture.talkers[:15])

    flows = "".join(
        f"<tr><td><code>{html.escape(f.label)}</code></td>"
        f"<td>{html.escape(f.sni or (f.http_hosts[0] if f.http_hosts else '-'))}</td>"
        f"<td>{fmt_bytes(f.total_bytes)}</td><td>{f.packets}</td></tr>"
        for f in sorted(capture.external_flows, key=lambda x: -x.total_bytes)[:20])

    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSentry Raporu</title><style>
 body {{ font-family:-apple-system,Segoe UI,Roboto,sans-serif; background:#0f1115;
        color:#e6e6e6; margin:0; padding:24px; }}
 h1 {{ font-size:22px; margin:0 0 4px; }} h2 {{ font-size:15px; margin:26px 0 10px; }}
 .sub {{ color:#9aa0a6; font-size:13px; margin-bottom:18px; }}
 .cards {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:18px; }}
 .card {{ background:#171a21; border:1px solid #262b36; border-radius:10px;
          padding:12px 16px; min-width:96px; }}
 .card b {{ display:block; font-size:20px; }} .card span {{ color:#9aa0a6; font-size:11px; }}
 table {{ width:100%; border-collapse:collapse; background:#171a21;
          border:1px solid #262b36; border-radius:10px; overflow:hidden; }}
 th,td {{ padding:9px 12px; border-bottom:1px solid #262b36; text-align:left;
          font-size:13px; vertical-align:top; }}
 th {{ background:#1d222b; color:#9aa0a6; font-size:11px; text-transform:uppercase; }}
 .lvl span {{ display:inline-block; padding:3px 9px; border-radius:20px;
              color:#fff; font-size:11px; font-weight:700; }}
 .title {{ font-weight:600; }} .d {{ color:#c9ced6; font-size:12px; margin:3px 0; }}
 ul {{ margin:4px 0 0; padding-left:16px; color:#9aa0a6; font-size:12px; }}
 code {{ font-family:ui-monospace,Menlo,Consolas,monospace; word-break:break-all; }}
 .score {{ text-align:right; font-weight:700; }}
</style></head><body>
<h1>NetSentry - Ag Trafigi Analiz Raporu</h1>
<div class="sub">{_stamp(capture.start_time)} - {_stamp(capture.end_time)}
  &middot; risk skoru {score}/100</div>
<div class="cards">{cards}</div>
<h2>Bulgular</h2>
<table><thead><tr><th>Seviye</th><th>Aciklama</th><th>Skor</th></tr></thead><tbody>{rows}</tbody></table>
<h2>En cok konusan kaynaklar</h2>
<table><thead><tr><th>IP</th><th>Veri</th><th>Konum</th></tr></thead><tbody>{talkers}</tbody></table>
<h2>En buyuk harici akislar</h2>
<table><thead><tr><th>Akis</th><th>Alan adi</th><th>Veri</th><th>Paket</th></tr></thead>
<tbody>{flows}</tbody></table>
</body></html>"""
