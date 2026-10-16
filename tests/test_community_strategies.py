# tests/test_community_strategies.py
"""База стратегий сообщества (core/community_strategies): разбор чужих
данных, порядок кандидатов, ссылка «Поделиться», кеш и подбор."""

import json
import os
import tempfile
import time
import unittest
import urllib.parse
from unittest import mock

from core import community_strategies as cs

NOW = time.mktime(time.strptime("2026-10-01", "%Y-%m-%d"))
GOOD = "--lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=6"


def item(**kw):
    x = {"id": "abc123", "asn": 12389, "provider": "Ростелеком",
         "proto": "tls", "steps": [GOOD], "targets": [], "reports": 3,
         "fails": 0, "last": "2026-09-20"}
    x.update(kw)
    return x


class TestParse(unittest.TestCase):

    def test_valid_item_kept(self):
        items = cs.parse_items({"items": [item(targets=[
            {"host": "YouTube.com"}, {"asn": 15169}, {"host": "bad host"},
            {"x": 1}])]}, 12389)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["steps"], [GOOD])
        self.assertEqual(items[0]["targets"], [{"host": "YouTube.com"},
                                               {"asn": 15169}])

    def test_bad_steps_drop_whole_item(self):
        bad = [
            item(steps=[GOOD, "--lua-desync=fake:blob=@/opt/x.bin"]),
            item(steps=["--hostlist=/etc/passwd"]),
            item(steps=["--lua-desync=fake:x=$(reboot)"]),
            item(steps=[]),
            item(steps=[GOOD] * 9),
            item(asn=1),
            item(proto="quic"),
            "мусор",
        ]
        self.assertEqual(cs.parse_items({"items": bad}, 12389), [])
        self.assertEqual(cs.parse_items(None, 12389), [])
        self.assertEqual(cs.parse_items({"items": "x"}, 12389), [])

    def test_text_fields_sanitized(self):
        x = cs.parse_items({"items": [item(provider="<b>x</b>",
                                           id="ZZab12!")]}, 12389)[0]
        self.assertEqual(x["provider"], "")
        self.assertEqual(x["id"], "ab12")


class TestRank(unittest.TestCase):

    def test_order_and_skip(self):
        site = item(id="a1", steps=["--lua-desync=a"], last="2026-09-01",
                    targets=[{"host": "rutracker.org"}], reports=1)
        net = item(id="b2", steps=["--lua-desync=b"], last="2026-09-01",
                   targets=[{"asn": 13335}], reports=5)
        popular = item(id="c3", steps=["--lua-desync=c"], last="2026-09-01",
                       reports=20)
        old = item(id="d4", steps=["--lua-desync=d"], last="2025-01-01",
                   targets=[{"host": "rutracker.org"}], reports=50)
        failed = item(id="e5", steps=["--lua-desync=e"], reports=1, fails=3)
        http = item(id="f6", steps=["--lua-desync=f"], proto="http")
        out = cs.candidates([old, popular, net, site, failed, http],
                            host="rutracker.org", host_asn=13335,
                            proto="tls", now=NOW)
        self.assertEqual([c["source_file"] for c in out],
                         ["community:a1", "community:b2", "community:c3",
                          "community:d4"])
        self.assertIn("открывала rutracker.org", out[0]["description"])
        self.assertIn("сети AS13335", out[1]["description"])
        self.assertIn("давно не подтверждалась", out[3]["description"])
        self.assertTrue(all(c["label"] == "community" for c in out))
        self.assertTrue(out[0]["id"].startswith("custom_"))
        self.assertEqual(len(cs.candidates([popular] * 20, now=NOW)), cs.MAX)

    def test_fresh_and_skipped(self):
        self.assertTrue(cs.fresh(item(last="2026-09-20"), NOW))
        self.assertFalse(cs.fresh(item(last="2026-01-01"), NOW))
        self.assertFalse(cs.fresh(item(last="мусор"), NOW))
        self.assertTrue(cs.skipped(item(reports=1, fails=2)))
        self.assertFalse(cs.skipped(item(reports=1, fails=1)))
        self.assertFalse(cs.skipped(item(reports=3, fails=2)))


class TestShare(unittest.TestCase):

    def test_share_url_fields(self):
        url, text = cs.share_url("zemidala/nfqws2-strategies", "works", {
            "asn": "AS12389", "provider": "Ростелеком", "proto": "tls",
            "target_host": "rutracker.org", "target_asn": 13335,
            "steps": [GOOD, "--hostlist=/x"], "result": "3/3"})
        self.assertTrue(url.startswith(
            "https://github.com/zemidala/nfqws2-strategies/issues/new?"))
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        self.assertEqual(q["template"], ["strategy.yml"])
        self.assertEqual(q["asn"], ["12389"])
        self.assertEqual(q["outcome"], ["works"])
        # Только шаги по шаблону: путь в базу не уходит.
        self.assertEqual(q["strategy"], [GOOD])
        self.assertEqual(q["title"], ["AS12389 · tls · rutracker.org"])
        self.assertIn("Сайт: rutracker.org · сеть AS13335", text)

    def test_confirm_and_fail_titles_and_bad_repo(self):
        url, _ = cs.share_url("x; rm", "fails", {"asn": 1, "steps": [GOOD],
                                                 "community": "ab"})
        self.assertIn(cs.DEFAULT_REPO, url)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        self.assertTrue(q["title"][0].startswith("Не сработала · AS1"))
        url, _ = cs.share_url(cs.DEFAULT_REPO, "works",
                              {"asn": 1, "steps": [GOOD], "community": "ab"})
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        self.assertTrue(q["title"][0].startswith("Подтверждаю · "))

    def test_share_rejects_paths(self):
        res = cs.share("works", "--filter-tcp=443 --lua-desync=fake:"
                                "blob=@/opt/x.bin")
        self.assertFalse(res["ok"])
        self.assertEqual(cs.steps_of("--filter-tcp=443 " + GOOD), [GOOD])


class TestProvider(unittest.TestCase):

    def test_detected_kept_in_temp_not_settings(self):
        tmp = tempfile.mkdtemp()
        cfg = mock.Mock()
        cfg.get.side_effect = lambda sec, key, default=None: default
        ripe = {"whats-my-ip": {"ip": "1.2.3.4"},
                "network-info": {"asns": ["12389"]},
                "as-overview": {"holder": "RT"}}
        with mock.patch.object(cs.tempfile, "gettempdir", return_value=tmp), \
                mock.patch.object(cs, "_cfg", return_value=cfg), \
                mock.patch.object(cs, "_ripe",
                                  side_effect=lambda n, r="", quick=False: ripe[n]):
            p = cs.provider(detect=True)
            self.assertEqual((p["asn"], p["provider"], p["auto"]),
                             (12389, "RT", True))
            cfg.set.assert_not_called()
            # Второй раз — из временного файла, без сети.
            with mock.patch.object(cs, "_ripe") as again:
                self.assertEqual(cs.provider(detect=True)["asn"], 12389)
            again.assert_not_called()

    def test_share_refuses_own_blob(self):
        res = cs.share("works", ["--blob=my:0x1603", "--filter-tcp=443",
                                 "--lua-desync=fake:blob=my"])
        self.assertFalse(res["ok"])
        self.assertIn("«my»", res["error"])


class TestLoad(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.p = mock.patch.object(cs.tempfile, "gettempdir",
                                   return_value=self.tmp)
        self.p.start()
        self.r = mock.patch.object(cs, "repo", return_value=cs.DEFAULT_REPO)
        self.r.start()

    def tearDown(self):
        self.p.stop()
        self.r.stop()

    def test_cache_and_404(self):
        body = json.dumps({"items": [item()]}).encode()
        with mock.patch.object(cs, "_get", return_value=(200, body)) as get:
            d = cs.load(12389)
            self.assertEqual(len(d["items"]), 1)
            cs.load(12389)
            self.assertEqual(get.call_count, 1)        # сутки из кеша
            self.assertIn("/main/data/AS12389.json", get.call_args[0][0])
        with mock.patch.object(cs, "_get", return_value=(404, b"")):
            d = cs.load(12389, force=True)
        self.assertEqual((d["items"], d["error"]), ([], ""))

    def test_error_kept_with_old_items(self):
        body = json.dumps({"items": [item()]}).encode()
        with mock.patch.object(cs, "_get", return_value=(200, body)):
            cs.load(12389)
        with mock.patch.object(cs, "_get", side_effect=OSError("timeout")):
            d = cs.load(12389, force=True)
        self.assertEqual(len(d["items"]), 1)
        self.assertIn("timeout", d["error"])


class TestScanner(unittest.TestCase):

    def test_community_first(self):
        from core.strategy_scanner import StrategyScanner
        sc = StrategyScanner()
        sc._protocol, sc._start_index, sc._target = "tcp", 0, "x.org"
        sc._community_req = True
        found = [{"id": "custom_1", "args": [GOOD], "name": "С", "label":
                  "community", "source_file": "community:ab",
                  "description": "сообщество"}]
        dup = mock.Mock()
        dup.get_args_list.return_value = [GOOD]
        other = mock.Mock()
        other.get_args_list.return_value = ["--lua-desync=x"]
        with mock.patch.object(cs, "scan_candidates",
                               return_value=(found, {"asn": 1, "count": 1,
                                                     "error": ""})):
            out = sc._community_first([dup, other], "tls")
        self.assertEqual(out[0].label, "community")
        self.assertEqual(out[0].source_file, "community:ab")
        self.assertEqual(out[1:], [other])
        self.assertEqual(sc.get_status()["community_first"], 1)
        # Выключено — ни сети, ни перестановки.
        sc._community_req = False
        with mock.patch.object(cs, "scan_candidates") as sc_call:
            self.assertEqual(sc._community_first([other], "tls"), [other])
        sc_call.assert_not_called()

    def test_order_memory_then_freeze_then_community(self):
        from core.strategy_scanner import StrategyScanner
        sc = StrategyScanner()
        calls = []
        sc._community_first = lambda e, f: calls.append("community") or e
        sc._freeze_first = lambda e, f: calls.append("freeze") or e
        sc._memory_first = lambda e: calls.append("memory") or e
        sc._custom = None
        sc._protocol, sc._mode, sc._target = "tcp", "quick", "x.org"
        sc._dpi_type, sc._start_index = "", 0
        cm = mock.Mock()
        cm.get_quick_set.return_value = []
        cm.get_catalog_entries.return_value = []
        with mock.patch("core.catalog_loader.get_catalog_manager",
                        return_value=cm):
            sc._select_strategies()
        # Каждый ставит своё в начало: последний вызванный — первым.
        self.assertEqual(calls, ["community", "freeze", "memory"])

    def test_resume_restores_even_when_unchecked(self):
        from core.strategy_scanner import StrategyScanner
        sc = StrategyScanner()
        sc._protocol, sc._start_index, sc._target = "tcp", 5, "x.org"
        sc._community_req = False
        saved = [{"id": "custom_1", "args": [GOOD], "label": "community"}]
        with mock.patch.object(sc, "_load_resume_state",
                               return_value={"community": saved}), \
                mock.patch.object(cs, "provider", return_value={"asn": 7}):
            out = sc._community_first([], "tls")
        self.assertEqual(len(out), 1)
        self.assertEqual(sc._community_info, {"asn": 7})

    def test_scan_candidates_lints(self):
        items = [item(id="a1"), item(id="b2", steps=["--lua-desync=nope"])]
        with mock.patch.object(cs, "provider",
                               return_value={"asn": 12389}), \
                mock.patch.object(cs, "load",
                                  return_value={"items": items,
                                                "error": ""}), \
                mock.patch.object(cs, "host_asn", return_value=0), \
                mock.patch("core.lint_env.known_functions",
                           return_value={"fake"}), \
                mock.patch("core.lint_env.known_blobs", return_value={}):
            kept, info = cs.scan_candidates("x.org")
        self.assertEqual([c["source_file"] for c in kept], ["community:a1"])
        self.assertEqual(info["count"], 2)


if __name__ == "__main__":
    unittest.main()
