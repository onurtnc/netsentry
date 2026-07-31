"""NetSentry komut satiri arayuzu."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List

from . import __version__
from .decode import decode
from .detect import (detect_beaconing, detect_exfiltration, run_all)
from .flows import build_capture
from .pcap import PcapError, read_packets
from .report import risk_score, to_console, to_html, to_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentry",
        description="PCAP dosyalarinda C2 beacon, DNS tuneli, tarama ve sizinti arar.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""ornekler:
  netsentry samples/ornek_trafik.pcap
  netsentry capture.pcapng --html rapor.html --json bulgular.json
  netsentry capture.pcap --dns          # sadece DNS sorgularini listele
  netsentry capture.pcap --flows        # akis tablosunu dok
  netsentry capture.pcap --fail-on high # CI icin exit code
""")
    parser.add_argument("pcap", help=".pcap veya .pcapng dosyasi")
    parser.add_argument("--json", metavar="PATH", help="JSON raporu yaz")
    parser.add_argument("--html", metavar="PATH", help="HTML raporu yaz")
    parser.add_argument("--dns", action="store_true", help="DNS sorgularini listele")
    parser.add_argument("--http", action="store_true", help="HTTP isteklerini listele")
    parser.add_argument("--flows", action="store_true", help="tum akislari listele")
    parser.add_argument("--top", type=int, default=10, help="tablolarda gosterilecek satir")
    parser.add_argument("--beacon-jitter", type=float, default=0.15,
                        help="beacon tespiti icin azami jitter orani (varsayilan 0.15)")
    parser.add_argument("--beacon-min-events", type=int, default=6,
                        help="beacon icin gereken en az baglanti sayisi (varsayilan 6)")
    parser.add_argument("--exfil-mb", type=float, default=1.0,
                        help="sizinti uyarisi icin giden veri esigi, MB (varsayilan 1)")
    parser.add_argument("--no-color", action="store_true", help="ANSI renklerini kapat")
    parser.add_argument("--quiet", action="store_true", help="konsol ciktisini bastir")
    parser.add_argument("--fail-on", default="none",
                        choices=["none", "low", "medium", "high", "critical"],
                        help="bu seviyede bulgu varsa exit code 1")
    parser.add_argument("-V", "--version", action="version", version=f"netsentry {__version__}")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.isfile(args.pcap):
        print(f"Dosya bulunamadi: {args.pcap}", file=sys.stderr)
        return 2

    try:
        decoded = [decode(p.index, p.timestamp, p.data, p.link_type, p.orig_len)
                   for p in read_packets(args.pcap)]
    except PcapError as exc:
        print(f"PCAP okunamadi: {exc}", file=sys.stderr)
        return 2

    capture = build_capture(d for d in decoded if d)

    findings = [f for f in run_all(capture) if f.code not in ("NS-BEACON", "NS-EXFIL")]
    findings += detect_beaconing(capture, min_events=args.beacon_min_events,
                                 max_jitter=args.beacon_jitter)
    findings += detect_exfiltration(capture, threshold=int(args.exfil_mb * 1024 * 1024))
    findings.sort(key=lambda f: -f.score)

    if args.dns:
        for query in capture.dns_queries:
            print(f"{query['timestamp']:.3f}\t{query['src_ip']}\t"
                  f"{query['type']}\t{query['name']}")
        return 0
    if args.http:
        for request in capture.http_requests:
            print(f"{request['timestamp']:.3f}\t{request['src_ip']}\t"
                  f"{request.get('method', '')}\t"
                  f"{request.get('host', request['dst_ip'])}{request.get('uri', '')}")
        return 0
    if args.flows:
        print(f"{'akis':<54}{'paket':>7}{'giden':>12}{'gelen':>12}")
        for flow in sorted(capture.flows.values(), key=lambda f: -f.total_bytes):
            print(f"{flow.label:<54}{flow.packets:>7}{flow.bytes_out:>12}{flow.bytes_in:>12}")
        return 0

    if not args.quiet:
        print(to_console(capture, findings, use_color=not args.no_color, top=args.top))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(capture, findings))
        print(f"JSON raporu -> {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(capture, findings))
        print(f"HTML raporu -> {args.html}")

    if args.fail_on != "none":
        from .detect import SEVERITY_SCORE
        floor = SEVERITY_SCORE[args.fail_on]
        if any(f.score >= floor for f in findings):
            return 1
    _ = risk_score(findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
