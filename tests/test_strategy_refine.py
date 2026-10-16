# tests/test_strategy_refine.py
"""«Уточнение» стратегии (core/strategy_refine): варианты фейка,
вариант полегче, база из подбора."""

import unittest
from unittest import mock

from core import strategy_refine as sr

BASE = ["--filter-tcp=443", "--blob=tls_google:@bin/tls_google.bin",
        "--lua-desync=fake:blob=tls_google:tcp_ts=-1000:repeats=6",
        "--lua-desync=multisplit:pos=1,midsld"]


def labels(vs):
    return [v["label"] for v in vs]


class TestHeavier(unittest.TestCase):

    def test_variants_of_fake(self):
        vs = sr.mutations(BASE, "tcp")
        ls = labels(vs)
        self.assertIn("повторов фейка: 11", ls)
        self.assertNotIn("повторов фейка: 6", ls)      # уже так
        self.assertIn("обман DPI: tcp_md5", ls)
        self.assertIn("подставное имя www.google.com", ls)
        self.assertLessEqual(len(vs), sr.MAX_VARIANTS)
        # Фильтр база не несёт — подбор ставит свой; blob-декларация — да.
        for v in vs:
            self.assertFalse(any(a.startswith("--filter") for a in v["args"]))
        md5 = next(v for v in vs if v["label"] == "обман DPI: tcp_md5")
        self.assertEqual(md5["args"][1],
                         "--lua-desync=fake:blob=tls_google:repeats=6:tcp_md5")
        self.assertEqual(md5["args"][0], BASE[1])
        # badack — только в паре с tcp_ts_up (линтер badack_without_ts_up).
        ack = next(v for v in vs if "tcp_ack" in v["label"])
        self.assertTrue(ack["args"][1].endswith(":tcp_ack=-66000:tcp_ts_up"),
                        ack["args"][1])

    def test_clone_variant(self):
        vs = sr.mutations(BASE, "tcp")
        v = next(v for v in vs if "ClientHello" in v["label"])
        self.assertEqual(v["args"][1],
                         "--lua-desync=tls_client_hello_clone:blob=ch_clone:"
                         "fallback=tls_google")
        self.assertIn("blob=ch_clone", v["args"][2])
        # Декларация tls_google остаётся: на неё ссылается fallback=.
        self.assertEqual(v["args"][0], BASE[1])

    def test_no_fake_adds_one(self):
        vs = sr.mutations(["--lua-desync=multisplit:pos=1"], "tcp")
        ls = labels(vs)
        self.assertEqual(ls[0], "добавить фейк")
        # Остальное — те же уточнения поверх добавленного фейка.
        self.assertTrue(all(l.startswith("фейк, ") for l in ls[1:]))
        self.assertLessEqual(len(vs), sr.MAX_VARIANTS)
        vs = sr.mutations(["--lua-desync=multisplit"], "udp")
        self.assertIn("fake_default_quic", vs[0]["args"][0])

    def test_udp_no_ttl_tricks(self):
        vs = sr.mutations(["--lua-desync=fake:blob=fake_default_quic"], "udp")
        self.assertTrue(all("повторов" in l for l in labels(vs)))

    def test_nothing_to_do(self):
        self.assertEqual(sr.mutations(["--filter-tcp=443"]), [])


class TestLighter(unittest.TestCase):

    def test_drop_steps_and_halve_repeats(self):
        vs = sr.mutations(BASE, "tcp", lighter=True)
        ls = labels(vs)
        self.assertEqual(ls[0], "как есть")
        self.assertIn("без шага fake", ls)
        self.assertIn("без шага multisplit", ls)
        self.assertIn("fake: повторов 3 вместо 6", ls)
        no_fake = next(v for v in vs if v["label"] == "без шага fake")
        self.assertEqual(no_fake["args"], ["--lua-desync=multisplit:pos=1,midsld"])


class TestPayloadPrefix(unittest.TestCase):

    def test_payload_prefix_kept(self):
        base = ["--payload=tls_client_hello",
                "--lua-desync=fake:blob=fake_default_tls",
                "--payload=all", "--lua-desync=multisplit:pos=1"]
        vs = sr.mutations(base, "tcp", lighter=True)
        no_fake = next(v for v in vs if v["label"] == "без шага fake")
        # Префикс снятого шага переходит к следующему.
        self.assertIn("--lua-desync=multisplit:pos=1", no_fake["args"])
        self.assertTrue(any(a.startswith("--payload=")
                            for a in no_fake["args"]))


class TestLinterClone(unittest.TestCase):

    def test_clone_blob_is_declared(self):
        from core import strategy_lint
        argv = ["--lua-desync=tls_client_hello_clone:blob=ch_clone:"
                "fallback=fake_default_tls",
                "--lua-desync=fake:blob=ch_clone"]
        codes = {f["code"] for f in strategy_lint.lint(
            argv, known_functions=None, known_blobs={})}
        self.assertNotIn("blob_unknown", codes)


class TestBase(unittest.TestCase):

    def test_refine_base_picks_furthest_failed_and_best_working(self):
        from core.models import CatalogEntry, StrategyProbeResult
        from core.strategy_scanner import StrategyScanner
        sc = StrategyScanner()

        def entry(sid, args):
            return CatalogEntry(section_id=sid, name=sid, description="",
                                author="", label="", blobs=[], args=args,
                                protocol="tcp", level="basic",
                                source_file="t")
        sc._entries_by_id = {"a": entry("a", "--lua-desync=fake"),
                             "b": entry("b", "--lua-desync=multisplit")}
        sc._results = [
            StrategyProbeResult("a", "a", "x.com", success=False, score=40),
            StrategyProbeResult("b", "b", "x.com", success=False, score=10)]
        sc._target, sc._protocol = "x.com", "tcp"
        base = sc.refine_base(False)
        self.assertEqual(base["strategy_id"], "a")
        self.assertIsNone(sc.refine_base(True))

    def test_start_feeds_scanner_custom(self):
        scanner = mock.Mock()
        scanner.refine_base.return_value = {
            "strategy_id": "a", "name": "A", "args": BASE, "score": 40,
            "target": "x.com", "protocol": "tcp"}
        scanner.start.return_value = True
        with mock.patch("core.strategy_scanner.get_strategy_scanner",
                        lambda: scanner), \
                mock.patch("core.lint_env.known_functions", lambda: None), \
                mock.patch("core.lint_env.known_blobs", lambda: None):
            r = sr.start(lighter=False)
        self.assertTrue(r["ok"])
        kw = scanner.start.call_args.kwargs
        self.assertEqual(kw["target"], "x.com")
        self.assertTrue(kw["custom"][0]["name"].startswith("Уточнение: "))


if __name__ == "__main__":
    unittest.main()
