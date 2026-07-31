"""NetSentry birim testleri."""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netsentry.decode import decode, parse_dns, parse_http_request, parse_tls_sni  # noqa: E402
from netsentry.detect import registered_domain, run_all, shannon_entropy  # noqa: E402
from netsentry.flows import build_capture, is_private  # noqa: E402
from netsentry.pcap import PcapError, read_packets, write_pcap  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "samples", "ornek_trafik.pcap")


def load_sample():
    packets = [decode(p.index, p.timestamp, p.data, p.link_type, p.orig_len)
               for p in read_packets(SAMPLE)]
    capture = build_capture(p for p in packets if p)
    return capture, run_all(capture)


class TestPcapIO(unittest.TestCase):
    def test_write_and_read_roundtrip(self):
        payload = b"\x00" * 60
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.pcap")
            write_pcap(path, iter([(1000.5, payload), (1001.25, payload)]))
            packets = list(read_packets(path))
        self.assertEqual(len(packets), 2)
        self.assertAlmostEqual(packets[0].timestamp, 1000.5, places=4)
        self.assertEqual(packets[1].data, payload)

    def test_invalid_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.pcap")
            with open(path, "wb") as fh:
                fh.write(b"NOTAPCAP" * 8)
            with self.assertRaises(PcapError):
                list(read_packets(path))

    def test_sample_exists_and_parses(self):
        packets = list(read_packets(SAMPLE))
        self.assertGreater(len(packets), 500)


class TestDecoders(unittest.TestCase):
    def test_dns_query_parse(self):
        query = (struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
                 + b"\x03www\x06python\x03org\x00" + struct.pack("!HH", 1, 1))
        parsed = parse_dns(query)
        self.assertEqual(parsed["questions"][0]["name"], "www.python.org")
        self.assertEqual(parsed["questions"][0]["type"], "A")
        self.assertFalse(parsed["is_response"])

    def test_http_request_parse(self):
        raw = (b"GET /a/b.exe HTTP/1.1\r\nHost: evil.top\r\n"
               b"User-Agent: curl/8.0\r\nAuthorization: Basic QQ==\r\n\r\n")
        parsed = parse_http_request(raw)
        self.assertEqual(parsed["method"], "GET")
        self.assertEqual(parsed["host"], "evil.top")
        self.assertEqual(parsed["user-agent"], "curl/8.0")
        self.assertIn("authorization", parsed)

    def test_tls_sni_extraction(self):
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        host = b"example.com"
        server_name = b"\x00" + struct.pack("!H", len(host)) + host
        body = struct.pack("!H", len(server_name)) + server_name
        ext = struct.pack("!HH", 0, len(body)) + body
        extensions = struct.pack("!H", len(ext)) + ext
        hello_body = (b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 2)
                      + b"\x13\x01" + b"\x01\x00" + extensions)
        handshake = b"\x01" + struct.pack("!I", len(hello_body))[1:] + hello_body
        record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
        self.assertEqual(parse_tls_sni(record), "example.com")

    def test_decode_returns_none_for_garbage(self):
        self.assertIsNone(decode(0, 0.0, b"\x00" * 4, 1))


class TestHelpers(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertGreater(shannon_entropy("a8f3k9zq2m"), 3.0)

    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.evil.top"), "evil.top")
        self.assertEqual(registered_domain("x.sirket.com.tr"), "sirket.com.tr")

    def test_is_private(self):
        self.assertTrue(is_private("10.0.0.1"))
        self.assertTrue(is_private("192.168.1.1"))
        self.assertFalse(is_private("8.8.8.8"))


class TestDetections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture, cls.findings = load_sample()
        cls.codes = {f.code for f in cls.findings}

    def test_capture_summary(self):
        self.assertGreater(self.capture.total_packets, 500)
        self.assertGreater(len(self.capture.dns_queries), 40)
        self.assertGreater(len(self.capture.flows), 10)

    def test_beacon_detected(self):
        self.assertIn("NS-BEACON", self.codes)
        beacon = next(f for f in self.findings if f.code == "NS-BEACON")
        self.assertEqual(beacon.entities["domain"], "cdn-telemetry.top")
        self.assertAlmostEqual(beacon.entities["interval_sec"], 60.0, delta=1.5)

    def test_no_false_beacon_on_normal_traffic(self):
        beacons = [f for f in self.findings if f.code == "NS-BEACON"]
        self.assertEqual(len(beacons), 1, "normal trafik beacon olarak isaretlenmemeli")

    def test_dns_tunnel_detected(self):
        self.assertIn("NS-DNSTUN", self.codes)
        tunnel = next(f for f in self.findings if f.code == "NS-DNSTUN")
        self.assertEqual(tunnel.entities["domain"], "datatransfer.xyz")

    def test_expected_detections_present(self):
        for code in ("NS-DGA", "NS-PORTSCAN", "NS-EXFIL", "NS-BADPORT",
                     "NS-CLEARAUTH", "NS-EXEDL", "NS-ICMPTUN", "NS-FTPCLEAR",
                     "NS-BADUA", "NS-BADTLD"):
            self.assertIn(code, self.codes, f"{code} tespit edilmedi")

    def test_portscan_details(self):
        scan = next(f for f in self.findings if f.code == "NS-PORTSCAN")
        self.assertEqual(scan.entities["src_ip"], "10.0.0.99")
        self.assertGreaterEqual(scan.entities["port_count"], 15)

    def test_tls_sni_collected(self):
        names = {t["sni"] for t in self.capture.tls_names}
        self.assertIn("cdn-telemetry.top", names)
        self.assertIn("github.com", names)

    def test_findings_sorted_by_severity(self):
        scores = [f.score for f in self.findings]
        self.assertEqual(scores, sorted(scores, reverse=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
