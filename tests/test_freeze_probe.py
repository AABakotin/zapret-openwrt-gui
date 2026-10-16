# tests/test_freeze_probe.py
"""Проба «обрыв на 16 КБ» (core/freeze_probe): сети, варианты, находки,
профиль сети и прогон с поддельной песочницей."""

import unittest
from unittest import mock

from core import freeze_probe as fp


TARGETS = [
    {"asn": "24940", "provider": "Hetzner", "url": "https://a.example/1"},
    {"asn": "24940", "provider": "Hetzner", "url": "https://a.example/2"},
    {"asn": "20473", "provider": "Vultr", "url": "https://b.example/1"},
    {"asn": "20473", "provider": "Constant", "url": "https://b.example/2"},
    {"asn": "63949", "provider": "Akamai HTTP", "url": "http://c.example/"},
    {"asn": "", "provider": "?", "url": "https://d.example/"},
]


class TestPure(unittest.TestCase):

    def test_networks_group_by_asn_https_only(self):
        nets = fp.networks(TARGETS)
        self.assertEqual([n["asn"] for n in nets], ["24940", "20473"])
        self.assertEqual(nets[0]["urls"], ["https://a.example/1",
                                           "https://a.example/2"])
        self.assertEqual(nets[1]["provider"], "Vultr / Constant")

    def test_variants_name_major_and_filtered(self):
        vs = fp.variants()
        self.assertEqual(len(vs), len(fp.TEMPLATES) * len(fp.NAMES))
        # Сначала все имена с первым приёмом.
        self.assertEqual([v["name"] for v in vs[:len(fp.NAMES)]],
                         list(fp.NAMES))
        self.assertIn("host=ya.ru", vs[0]["steps"][0])
        only_fake = fp.variants({"fake"})
        self.assertEqual(len(only_fake), len(fp.NAMES))
        self.assertIn("sni=ya.ru", only_fake[0]["steps"][0])

    def test_candidates_merge_and_order(self):
        a = ["--lua-desync=hostfakesplit:host=ya.ru"]
        b = ["--lua-desync=hostfakesplit:host=vk.com"]
        state = {"nets": [
            {"asn": "1", "provider": "X", "found": {"name": "vk.com",
                                                   "steps": b}},
            {"asn": "2", "provider": "Y", "found": {"name": "ya.ru",
                                                   "steps": a}},
            {"asn": "3", "provider": "Z", "found": {"name": "ya.ru",
                                                   "steps": a}},
            {"asn": "4", "provider": "W", "found": None},
        ]}
        cs = fp.candidates(state)
        self.assertEqual([c["args"] for c in cs], [a, b])
        self.assertTrue(cs[0]["id"].startswith("custom_"))
        self.assertIn("AS2 Y", cs[0]["description"])
        self.assertIn("AS3 Z", cs[0]["description"])
        self.assertEqual(fp.candidates({}), [])

    def test_network_profile_and_strategy(self):
        net = {"asn": "24940", "provider": "Hetzner",
               "found": {"steps": ["--lua-desync=hostfakesplit:host=ya.ru"]}}
        prof = fp.network_profile(net, "asn24940")
        self.assertEqual(prof["args"],
                         "--filter-tcp=443 --filter-l7=tls "
                         "--ipset=lists/asn24940.txt --payload=tls_client_hello "
                         "--lua-desync=hostfakesplit:host=ya.ru")
        base = {"id": "my", "name": "Моя", "profiles": [
            {"id": "p1", "args": "--filter-tcp=443 --lua-desync=fake"}]}
        st = fp.with_profile(base, prof)
        self.assertEqual(st["id"], "net16k-my")
        self.assertEqual([p["id"] for p in st["profiles"]],
                         ["net16k-asn24940", "p1"])
        # Повторное применение правит ту же стратегию, без дубля профиля.
        again = fp.with_profile(st, prof)
        self.assertEqual(again["id"], "net16k-my")
        self.assertEqual([p["id"] for p in again["profiles"]],
                         ["net16k-asn24940", "p1"])
        # Без текущей стратегии — только профиль сети.
        alone = fp.with_profile(None, prof)
        self.assertEqual(alone["id"], "net16k-only")
        self.assertEqual(len(alone["profiles"]), 1)

    def test_profile_passes_linter(self):
        from core import strategy_lint
        net = {"asn": "1", "provider": "X",
               "found": {"steps": fp.variants()[0]["steps"]}}
        argv = fp.network_profile(net, "asn1")["args"].split()
        errors = [f for f in strategy_lint.lint(argv)
                  if f.get("severity") == "error"]
        self.assertEqual(errors, [])


class FakeSandbox:
    def __init__(self, good):
        self.good = good
        self.args = None
        self.started = []

    def start(self, args):
        self.args = args
        self.started.append(args)
        return True

    def is_running(self):
        return True

    def stop(self):
        self.args = None


class TestRun(unittest.TestCase):

    def setUp(self):
        fp._stop.clear()
        fp._status.clear()
        self.nets = fp.networks(TARGETS)
        fp._status.update({"state": "running", "nets": [
            dict(n, verdict="", found=None, tried=0, url="")
            for n in self.nets], "done": 0, "total": 2})

    def tearDown(self):
        fp._status.clear()
        fp._status["state"] = "idle"

    def _run(self, good_name):
        sandbox = FakeSandbox(good_name)

        def probe(url, mark):
            if mark == 0:          # без обхода: у Hetzner обрыв
                return "freeze" if "a.example" in url else "ok"
            args = " ".join(sandbox.args or [])
            return "ok" if good_name in args else "freeze"

        fw = mock.Mock()
        fw.apply_sandbox_rules.return_value = True
        with mock.patch.object(fp, "_probe", side_effect=probe), \
                mock.patch.object(fp.time, "sleep"), \
                mock.patch("core.nfqws_sandbox.NFQWSSandbox",
                           return_value=sandbox), \
                mock.patch("core.firewall.get_firewall_manager",
                           return_value=fw), \
                mock.patch("core.lint_env.known_functions",
                           return_value=None):
            fp._run_locked({"baseline_mark": 0, "sandbox_mark": 8,
                            "queue": 301})
        return sandbox, fw

    def test_finds_name_for_frozen_net(self):
        sandbox, fw = self._run("host=hcaptcha.com")
        hetzner, vultr = fp._status["nets"]
        self.assertEqual(hetzner["verdict"], "freeze")
        self.assertEqual(vultr["verdict"], "ok")
        self.assertEqual(hetzner["found"]["name"], "hcaptcha.com")
        self.assertEqual(hetzner["tried"], 3)       # ya.ru, 300.ya.ru, hcaptcha
        self.assertIsNone(vultr["found"])
        # Песочница — с фильтром TLS и только на шагах кандидата.
        self.assertEqual(sandbox.started[0][:3], list(fp.FILTER) + [fp.PAYLOAD])
        fw.remove_sandbox_rules.assert_called_once()

    def test_nothing_frozen_no_sandbox(self):
        fp._status["nets"] = [dict(n, verdict="", found=None, tried=0,
                                   url="") for n in self.nets[1:]]
        sandbox, fw = self._run("x")
        fw.apply_sandbox_rules.assert_not_called()
        self.assertEqual(sandbox.started, [])


class TestScannerFirst(unittest.TestCase):

    def test_freeze_entries_go_first_for_tls(self):
        from core.strategy_scanner import StrategyScanner
        sc = StrategyScanner.__new__(StrategyScanner)
        sc._protocol, sc._start_index = "tcp", 0
        found = [{"id": "custom_abc", "args": ["--lua-desync=fake"],
                  "name": "Обрыв 16 КБ: fake", "description": "d"}]
        with mock.patch.object(fp, "candidates", return_value=found), \
                mock.patch.object(fp, "load", return_value={}):
            out = sc._freeze_first(["x"], "tls")
            self.assertEqual(out[0].section_id, "custom_abc")
            self.assertEqual(out[0].description, "d")
            self.assertEqual(out[1:], ["x"])
            self.assertEqual(sc._freeze, found)
            # QUIC/HTTP — не трогаем.
            self.assertEqual(sc._freeze_first(["x"], "http"), ["x"])


class TestApply(unittest.TestCase):

    def test_apply_network(self):
        state = {"nets": [{"asn": "24940", "provider": "Hetzner",
                           "found": {"name": "ya.ru", "steps": [
                               "--lua-desync=hostfakesplit:host=ya.ru"]}}]}
        ipm = mock.Mock()
        ipm.load_by_asn.return_value = ["5.9.0.0/16"]
        ipm.save_ipset.return_value = True
        sm = mock.Mock()
        sm.get_strategy.return_value = {"id": "cur", "name": "Cur",
                                        "profiles": []}
        sm.save_user_strategy.side_effect = lambda d: d
        cfg = mock.Mock()
        cfg.get.return_value = "cur"
        with mock.patch.object(fp, "load", return_value=state), \
                mock.patch("core.ipset_manager.get_ipset_manager",
                           return_value=ipm), \
                mock.patch("core.strategy_builder.get_strategy_manager",
                           return_value=sm), \
                mock.patch("core.config_manager.get_config_manager",
                           return_value=cfg), \
                mock.patch("core.safe_apply.start",
                           return_value={"ok": True}) as start:
            res = fp.apply_network("AS24940")
        self.assertTrue(res["ok"])
        start.assert_called_once_with("net16k-cur")
        ipm.save_ipset.assert_called_once_with("asn24940", ["5.9.0.0/16"])
        saved = sm.save_user_strategy.call_args[0][0]
        self.assertIn("--ipset=lists/asn24940.txt",
                      saved["profiles"][0]["args"])

    def test_apply_unknown_asn(self):
        with mock.patch.object(fp, "load", return_value={}):
            self.assertFalse(fp.apply_network("1")["ok"])


if __name__ == "__main__":
    unittest.main()
