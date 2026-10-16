# tests/test_custom_candidates.py
"""«Своя стратегия» в подборе (core/custom_candidates): текст из чата →
кандидаты сканера, отбраковка до запуска."""

import unittest

from core import custom_candidates as cc

FUNCS = {"fake", "multisplit", "multidisorder", "fakedsplit"}
BLOBS = {"tls_google": True}


def check(text, protocol="tcp"):
    return cc.check(text, protocol, known_functions=FUNCS, known_blobs=BLOBS)


class TestSplit(unittest.TestCase):

    def test_chat_text_with_quotes_and_signature(self):
        text = ('У меня на Ростелекоме работает:\n'
                '«--filter-tcp=443 --hostlist=/opt/x.txt '
                '--lua-desync=fake:blob=fake_default_tls:repeats=6 '
                '--lua-desync=multisplit:pos=2»')
        r = check(text)
        self.assertTrue(r["ok"])
        self.assertEqual(r["candidates"][0]["args"], [
            "--lua-desync=fake:blob=fake_default_tls:repeats=6",
            "--lua-desync=multisplit:pos=2"])

    def test_new_and_blank_lines_split(self):
        text = ('nfqws2 --qnum=200 --lua-desync=fake:blob=tls_google --new '
                '--lua-desync=multisplit:pos=1\n\n'
                'NFQWS2_OPT="--lua-desync=multidisorder:pos=midsld"')
        r = check(text)
        self.assertEqual(len(r["candidates"]), 3)

    def test_line_continuation_is_not_a_boundary(self):
        r = check("--lua-desync=fake:blob=tls_google \\\n"
                  "--lua-desync=multisplit:pos=1")
        self.assertEqual(len(r["candidates"]), 1)
        self.assertEqual(len(r["candidates"][0]["args"]), 2)

    def test_quoted_value(self):
        r = check('--lua-desync="multisplit:pos=1"')
        self.assertEqual(r["candidates"][0]["args"],
                         ["--lua-desync=multisplit:pos=1"])

    def test_duplicates_once(self):
        r = check("--lua-desync=multisplit:pos=1\n\n"
                  "--lua-desync=multisplit:pos=1")
        self.assertEqual(len(r["candidates"]), 1)
        self.assertEqual(r["rejected"][0]["reason"], "повтор части 1")

    def test_inline_blob_travels_with_part(self):
        r = check("--blob=myfake:0x1603030001 --new "
                  "--lua-desync=fake:blob=myfake --new "
                  "--lua-desync=multisplit")
        self.assertEqual(r["candidates"][0]["args"], [
            "--blob=myfake:0x1603030001", "--lua-desync=fake:blob=myfake"])
        self.assertEqual(r["candidates"][1]["args"],
                         ["--lua-desync=multisplit"])

    def test_file_blob_named(self):
        r = check("--blob=my:@/opt/etc/nfqws2/my.bin "
                  "--lua-desync=fake:blob=my")
        self.assertFalse(r["ok"])
        self.assertIn("чужого роутера", r["rejected"][0]["reason"])

    def test_l7_marks_protocol(self):
        r = check("--filter-l7=quic --lua-desync=fake:blob=fake_default_quic",
                  "tcp")
        self.assertFalse(r["ok"])
        self.assertIn("UDP", r["rejected"][0]["reason"])

    def test_too_long(self):
        r = check("x" * (cc.MAX_TEXT + 1))
        self.assertFalse(r["ok"])
        self.assertIn("длиннее", r["error"])

    def test_cap(self):
        text = "\n\n".join("--lua-desync=multisplit:pos=%d" % i
                           for i in range(1, 14))
        r = check(text)
        self.assertEqual(len(r["candidates"]), cc.MAX_CANDIDATES)
        self.assertEqual(r["dropped"], 3)


class TestReject(unittest.TestCase):

    def test_unknown_function(self):
        r = check("--lua-desync=nosuchfn:x=1\n\n--lua-desync=fake")
        self.assertEqual(len(r["candidates"]), 1)
        self.assertIn("nosuchfn", r["rejected"][0]["reason"])

    def test_unknown_blob(self):
        r = check("--lua-desync=fake:blob=my_secret_blob")
        self.assertFalse(r["ok"])
        self.assertIn("my_secret_blob", r["rejected"][0]["reason"])

    def test_v1_named(self):
        r = check("--dpi-desync=fake,split2 --dpi-desync-ttl=5")
        self.assertFalse(r["ok"])
        self.assertIn("v1", r["rejected"][0]["reason"])

    def test_protocol_mismatch(self):
        text = ("--filter-udp=443 --lua-desync=fake:blob=fake_default_quic"
                " --new --filter-tcp=443 --lua-desync=multisplit")
        r = check(text, "tcp")
        self.assertEqual(len(r["candidates"]), 1)
        self.assertIn("UDP", r["rejected"][0]["reason"])
        r = check(text, "udp")
        self.assertEqual(r["candidates"][0]["args"],
                         ["--lua-desync=fake:blob=fake_default_quic"])

    def test_nothing(self):
        r = check("привет")
        self.assertFalse(r["ok"])
        self.assertIn("--lua-desync", r["error"])


class TestEntries(unittest.TestCase):

    def test_entries_and_scanner_selection(self):
        from core.strategy_scanner import StrategyScanner
        r = check("--lua-desync=multisplit:pos=1\n\n--lua-desync=fake")
        sc = StrategyScanner()
        sc._custom = r["candidates"]
        sc._protocol = "tcp"
        sc._start_index = 0
        got = sc._select_strategies()
        self.assertEqual([e.get_args_list() for e in got],
                         [["--lua-desync=multisplit:pos=1"],
                          ["--lua-desync=fake"]])
        self.assertEqual(got[0].level, "custom")
        self.assertTrue(got[0].section_id.startswith("custom_"))

    def test_custom_find_can_be_saved(self):
        from unittest import mock
        from core.models import StrategyProbeResult
        from core.strategy_scanner import StrategyScanner
        r = check("--lua-desync=multisplit:pos=1")
        sc = StrategyScanner()
        entry = cc.entries(r["candidates"])[0]
        sc._entries_by_id = {entry.section_id: entry}
        res = StrategyProbeResult(strategy_id=entry.section_id,
                                  strategy_name=entry.name, target="x.com")
        saved = {}
        sm = mock.Mock()
        sm.save_user_strategy.side_effect = lambda d: saved.update(d) or d
        with mock.patch("core.catalog_loader.get_catalog_manager") as cm, \
                mock.patch("core.strategy_builder.get_strategy_manager",
                           lambda: sm), \
                mock.patch.object(sc, "_build_strategy_args",
                                  lambda e: e.get_args_list()), \
                mock.patch.object(sc, "_materialize_tmp_hostlist",
                                  lambda a, p: a):
            cm.return_value.get_entry_by_id.return_value = None
            self.assertTrue(sc._save_probe_result(res))
        self.assertEqual(saved["profiles"][0]["args"],
                         "--lua-desync=multisplit:pos=1")


if __name__ == "__main__":
    unittest.main()
