# tests/test_site_trace.py
"""«Куда пойдёт сайт» (core/site_trace): разбор профилей nfqws2 и выбор
профиля для потока — чистые функции, плюс граница trace()."""

import unittest
from unittest import mock

from core import site_trace as st

HTTPS = ("https", "tcp", 443, "tls")
QUIC = ("quic", "udp", 443, "quic")
HTTP = ("http", "tcp", 80, "http")


def reader(lists):
    return lambda path: set(lists.get(path, ()))


class TestPorts(unittest.TestCase):

    def test_parse(self):
        self.assertEqual(st.parse_ports("80,443,1000-2000"),
                         [(80, 80, False), (443, 443, False),
                          (1000, 2000, False)])
        self.assertEqual(st.parse_ports("~80"), [(80, 80, True)])
        self.assertEqual(st.parse_ports("*"), [(0, 65535, False)])
        self.assertEqual(st.parse_ports("50000:50100,x"),
                         [(50000, 50100, False)])

    def test_port_in(self):
        self.assertTrue(st.port_in(st.parse_ports("80,443"), 443))
        self.assertFalse(st.port_in(st.parse_ports("80"), 443))
        self.assertTrue(st.port_in(st.parse_ports("~80"), 443))
        self.assertFalse(st.port_in(st.parse_ports("~80"), 80))


class TestMatch(unittest.TestCase):

    def test_domain_hit(self):
        self.assertEqual(st.domain_hit("a.youtube.com", ["youtube.com"]),
                         "youtube.com")
        self.assertEqual(st.domain_hit("youtube.com", ["youtube.com"]),
                         "youtube.com")
        self.assertEqual(st.domain_hit("a.youtube.com", ["^youtube.com"]),
                         "")
        self.assertEqual(st.domain_hit("youtube.com", ["^youtube.com"]),
                         "^youtube.com")
        self.assertEqual(st.domain_hit("notyoutube.com", ["youtube.com"]),
                         "")

    def test_ip_hit(self):
        self.assertIn("10.0.0.0/8", st.ip_hit(["10.1.2.3"], ["10.0.0.0/8"]))
        self.assertEqual(st.ip_hit(["1.1.1.1"], ["10.0.0.0/8", "bad"]), "")
        self.assertEqual(st.ip_hit(["::1"], ["0.0.0.0/0"]), "")


class TestProfiles(unittest.TestCase):

    def pick(self, profiles, flow=HTTPS, domain="youtube.com",
             ips=("1.2.3.4",), lists=None):
        return st.pick_profile(profiles, flow, domain, list(ips),
                               reader(lists or {}))

    def test_parse_profile(self):
        p = st.parse_profile([
            "--filter-tcp=443", "--filter-l7=tls,quic",
            "--hostlist=/l/a.txt", "--hostlist-domains=X.com",
            "--lua-desync=fake:blob=tls", "--lua-desync=multisplit"])
        self.assertEqual(p["tcp"], [(443, 443, False)])
        self.assertEqual(p["l7"], {"tls", "quic"})
        self.assertEqual(p["hostlist_domains"], ["x.com"])
        self.assertEqual(p["actions"], ["fake", "multisplit"])

    def test_first_matching_profile_wins(self):
        r = self.pick([
            ["--filter-udp=443", "--lua-desync=fake"],
            ["--filter-tcp=443", "--hostlist=/l/yt.txt",
             "--lua-desync=multisplit"],
            ["--filter-tcp=443", "--lua-desync=fake"],
        ], lists={"/l/yt.txt": ["youtube.com"]})
        self.assertEqual(r["profile"], 2)
        self.assertEqual(r["actions"], ["multisplit"])
        self.assertEqual(r["skipped"][0]["reason"],
                         "фильтр только по UDP")
        self.assertIn("yt.txt", r["reason"])

    def test_exclude_beats_include(self):
        r = self.pick([["--filter-tcp=443", "--hostlist-domains=youtube.com",
                        "--hostlist-exclude=/l/ex.txt"]],
                      lists={"/l/ex.txt": ["youtube.com"]})
        self.assertIsNone(r["profile"])
        self.assertIn("исключён", r["skipped"][0]["reason"])

    def test_l7_filter(self):
        prof = [["--filter-l7=http", "--lua-desync=fake"]]
        self.assertIsNone(self.pick(prof)["profile"])
        self.assertEqual(self.pick(prof, flow=HTTP)["profile"], 1)

    def test_l3_multi_value(self):
        prof = [["--filter-l3=ipv4,ipv6", "--lua-desync=fake"]]
        self.assertEqual(self.pick(prof)["profile"], 1)
        self.assertIsNone(self.pick([["--filter-l3=ipv6"]])["profile"])

    def test_no_lists_takes_all(self):
        r = self.pick([["--filter-udp=443", "--lua-desync=fake"]], flow=QUIC)
        self.assertEqual(r["profile"], 1)

    def test_ipset_and_hostlist_both_required(self):
        prof = [["--ipset-ip=10.0.0.0/8", "--hostlist-domains=youtube.com"]]
        self.assertIsNone(self.pick(prof)["profile"])
        self.assertEqual(self.pick(prof, ips=["10.1.1.1"])["profile"], 1)
        r = self.pick([["--ipset-ip=10.0.0.0/8"]], ips=[])
        self.assertIn("не узнаны", r["skipped"][0]["reason"])

    def test_autohostlist_note(self):
        r = self.pick([["--hostlist-auto=/l/auto.txt"]])
        self.assertIn("автохостлист", r["skipped"][0]["reason"])
        r = self.pick([["--hostlist-auto=/l/auto.txt"]],
                      lists={"/l/auto.txt": ["youtube.com"]})
        self.assertEqual(r["profile"], 1)

    def test_nothing_matches(self):
        r = self.pick([["--hostlist-domains=example.com"]])
        self.assertIsNone(r["profile"])
        self.assertIn("без обхода", r["reason"])


class TestTrace(unittest.TestCase):

    def test_bad_domain(self):
        self.assertFalse(st.trace("localhost")["ok"])

    def test_normalize(self):
        self.assertEqual(st.normalize("https://WWW.YouTube.com/watch?v=1"),
                         "www.youtube.com")

    def test_layer_errors_do_not_break(self):
        boom = mock.Mock(side_effect=RuntimeError("x"))
        with mock.patch.object(st, "_hosts_layer", boom), \
                mock.patch.object(st, "_dns_layer", lambda d: []), \
                mock.patch.object(st, "_unified_layer", lambda d: []), \
                mock.patch.object(st, "_lists_layer", lambda d: {}), \
                mock.patch("core.list_lint._current_argv", lambda: []):
            r = st.trace("youtube.com", resolve=False)
        self.assertTrue(r["ok"])
        self.assertIn("hosts", r["errors"])
        self.assertTrue(r["nfqws"]["no_strategy"])
        self.assertIsInstance(r["summary"], list)


if __name__ == "__main__":
    unittest.main()
