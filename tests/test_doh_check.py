# tests/test_doh_check.py
"""Сверка DNS роутера с DoH: двоичный DNS и вердикт (core/testers/doh_check)."""

import struct
import unittest
from unittest import mock

from core.testers import doh_check as dc


def _answer(query, ips, rcode=0):
    """Ответ сервера на query: тот же вопрос + A-записи через указатель."""
    qid = struct.unpack("!H", query[:2])[0]
    header = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(ips), 0, 0)
    body = query[12:]
    for ip in ips:
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + \
            bytes(int(x) for x in ip.split("."))
    return header + body


class TestWire(unittest.TestCase):

    def test_build_query(self):
        q = dc.build_query("rutracker.org", qid=0x1234)
        self.assertEqual(q[:2], b"\x12\x34")
        self.assertIn(b"\x09rutracker\x03org\x00", q)
        self.assertTrue(q.endswith(b"\x00\x01\x00\x01"))

    def test_bad_names(self):
        for bad in ("", "a..b", "x" * 64 + ".com"):
            with self.assertRaises(ValueError):
                dc.build_query(bad)

    def test_parse_roundtrip(self):
        q = dc.build_query("example.com")
        self.assertEqual(dc.parse_answer(_answer(q, ["93.184.216.34",
                                                     "1.2.3.4"])),
                         ["93.184.216.34", "1.2.3.4"])

    def test_nxdomain_is_empty(self):
        q = dc.build_query("nope.example")
        self.assertEqual(dc.parse_answer(_answer(q, [], rcode=3)), [])

    def test_servfail_raises(self):
        q = dc.build_query("x.example")
        with self.assertRaises(ValueError):
            dc.parse_answer(_answer(q, [], rcode=2))

    def test_truncated_raises(self):
        q = dc.build_query("x.example")
        with self.assertRaises(ValueError):
            dc.parse_answer(_answer(q, ["1.2.3.4"])[:-3])


class TestVerdict(unittest.TestCase):

    def test_match(self):
        self.assertEqual(dc.verdict(["1.1.1.1"], ["1.1.1.1", "2.2.2.2"])["kind"],
                         "match")

    def test_differs_without_network_check(self):
        v = dc.verdict(["1.1.1.1"], ["2.2.2.2"])
        self.assertEqual(v["kind"], "differs")
        self.assertFalse(v["fake"])

    def test_cdn_both_open(self):
        v = dc.verdict(["1.1.1.1"], ["2.2.2.2"], ["1.1.1.1"], ["2.2.2.2"])
        self.assertEqual(v["kind"], "differs")
        self.assertFalse(v["fake"])

    def test_spoofed(self):
        v = dc.verdict(["5.5.5.5"], ["8.8.4.4"], [], ["8.8.4.4"])
        self.assertEqual(v["kind"], "spoofed")
        self.assertTrue(v["fake"])
        self.assertIn("5.5.5.5", v["reason"])

    def test_closed_addr_partial_overlap(self):
        v = dc.verdict(["5.5.5.5", "8.8.4.4"], ["8.8.4.4", "8.8.8.8"],
                       [], ["8.8.8.8"])
        self.assertEqual(v["kind"], "closed_addr")
        self.assertTrue(v["fake"])

    def test_everything_closed_is_not_dns(self):
        v = dc.verdict(["5.5.5.5"], ["8.8.4.4"], [], [])
        self.assertFalse(v["fake"])

    def test_nothing_to_compare(self):
        self.assertEqual(dc.verdict([], ["1.1.1.1"])["kind"], "unknown")
        self.assertEqual(dc.verdict(["1.1.1.1"], [])["kind"], "unknown")


class TestCrossCheck(unittest.TestCase):

    def test_ipv6_ignored_and_no_connect_when_match(self):
        with mock.patch.object(dc, "resolve", return_value={
                "ok": True, "ips": ["1.1.1.1"], "provider": "Яндекс",
                "error": ""}), \
             mock.patch.object(dc, "reachable") as reach:
            out = dc.cross_check("x.ru", ["1.1.1.1", "2a00::1"])
        self.assertEqual(out["kind"], "match")
        reach.assert_not_called()

    def test_spoof_flow(self):
        with mock.patch.object(dc, "resolve", return_value={
                "ok": True, "ips": ["8.8.4.4"], "provider": "Google",
                "error": ""}), \
             mock.patch.object(dc, "reachable",
                               side_effect=[[], ["8.8.4.4"]]):
            out = dc.cross_check("x.ru", ["5.5.5.5"])
        self.assertTrue(out["fake"])
        self.assertEqual(out["provider"], "Google")

    def test_resolve_falls_through_providers(self):
        calls = []

        def fake_query(url, name, timeout):
            calls.append(url)
            if "yandex" in url:
                raise OSError("timeout")
            return ["9.9.9.9"]
        with mock.patch.object(dc, "_query", side_effect=fake_query):
            r = dc.resolve("x.ru")
        self.assertTrue(r["ok"])
        self.assertEqual(r["provider"], "Google")
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
