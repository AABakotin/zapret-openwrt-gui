# tests/test_autopick.py
"""Автоподбор по мониторингу (core/autopick) и автоприменение с проверкой."""

import shutil
import tempfile
import time
import unittest
from unittest import mock

from core import autopick as ap
from core import safe_apply as sa


class Case(unittest.TestCase):

    def setUp(self):
        import core.config_manager as cm
        self.dir = tempfile.mkdtemp(prefix="autopick-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        self.cfg = cm._config_manager
        ap._running["key"] = ""
        ap._pending.clear()
        self.addCleanup(ap._pending.clear)
        self.notes = []
        p = mock.patch.object(ap, "_notify", self.notes.append)
        p.start()
        self.addCleanup(p.stop)


class TestPure(unittest.TestCase):

    def test_should_run(self):
        now = time.time()
        self.assertIn("выключен", ap.should_run("x", now, 0, "off", 6))
        self.assertIn("занято", ap.should_run("x", now, 0, "suggest", 6,
                                              busy="скан"))
        self.assertIn("недавно", ap.should_run("x", now, now - 60,
                                               "apply", 6))
        self.assertEqual(ap.should_run("x", now, now - 7 * 3600,
                                       "apply", 6), "")

    def test_best(self):
        self.assertIsNone(ap.best([]))
        top = ap.best([{"strategy_id": "a", "score": 1, "latency_ms": 5},
                       {"strategy_id": "b", "score": 3, "latency_ms": 90},
                       {"strategy_id": "c", "score": 3, "latency_ms": 10}])
        self.assertEqual(top["strategy_id"], "c")

    def test_auto_verdict(self):
        ok = {"sites": {"X": True, "Y": True}}
        self.assertEqual(sa.auto_verdict("X", ok, {"lost": []}), "")
        self.assertIn("перестали", sa.auto_verdict("X", ok, {"lost": ["Y"]}))
        self.assertIn("не открылся", sa.auto_verdict(
            "X", {"sites": {"X": False}}, {"lost": []}))


class FakeScanner:
    def __init__(self, working, final="completed"):
        self.working = working
        self.final = final
        self.started = None

    def start(self, **kw):
        self.started = kw
        return True

    def get_status(self):
        return {"status": self.final}

    def get_working_strategies(self):
        return self.working

    def save_working_by_id(self, sid):
        return {"id": "scan_" + sid, "name": "[Scan] " + sid}


class TestRun(Case):

    def _run(self, mode, working, final="completed"):
        sc = FakeScanner(working, final)
        with mock.patch("core.strategy_scanner.get_strategy_scanner",
                        lambda: sc):
            ap._running["key"] = "YouTube"
            ap._run("YouTube", "youtube.com", mode)
        return sc

    def test_trigger_off_does_nothing(self):
        self.cfg.set("healthcheck", "autopick", {"mode": "off"})
        self.assertFalse(ap.trigger("YouTube", ["youtube.com"])["ok"])

    def test_busy_trigger_is_deferred(self):
        self.cfg.set("healthcheck", "autopick", {"mode": "suggest"})
        with mock.patch.object(ap, "_busy", lambda: "идёт подбор"):
            r = ap.trigger("YouTube", ["youtube.com"])
        self.assertFalse(r["ok"])
        self.assertTrue(ap.pending("YouTube"))

    def test_scanner_refusal_keeps_interval(self):
        ap._set_run("YouTube", ts=123.0, result="nothing")
        sc = FakeScanner([])
        sc.start = lambda **kw: False
        sc.refusal = "занят другим"
        with mock.patch("core.strategy_scanner.get_strategy_scanner",
                        lambda: sc):
            ap._running["key"] = "YouTube"
            ap._run("YouTube", "youtube.com", "suggest", 123.0)
        run = ap.status()["runs"]["YouTube"]
        self.assertEqual(run["result"], "deferred")
        self.assertEqual(run["ts"], 123.0)
        self.assertTrue(ap.pending("YouTube"))

    def test_trigger_needs_sandbox(self):
        self.cfg.set("healthcheck", "autopick", {"mode": "suggest"})
        with mock.patch.object(ap, "_busy", lambda: ""), \
                mock.patch("core.nfqws_sandbox.available",
                           lambda: {"ok": False, "reason": "нет метки"}):
            r = ap.trigger("YouTube", ["youtube.com"])
        self.assertFalse(r["ok"])
        self.assertIn("песочницы", r["reason"])
        self.assertEqual(ap.status()["runs"]["YouTube"]["result"], "skipped")

    def test_suggest_stores_suggestion(self):
        sc = self._run("suggest", [{"strategy_id": "s1", "score": 2}])
        self.assertEqual(sc.started["target"], "youtube.com")
        self.assertTrue(sc.started["require_isolation"])
        st = ap.status()
        self.assertEqual(st["suggestions"][0]["strategy_id"], "scan_s1")
        self.assertEqual(st["runs"]["YouTube"]["result"], "suggested")
        self.assertIsNone(st["running"])
        self.assertTrue(self.notes)

    def test_nothing_found(self):
        self._run("suggest", [])
        self.assertEqual(ap.status()["runs"]["YouTube"]["result"], "nothing")
        self.assertEqual(ap.status()["suggestions"], [])

    def test_scan_error_is_error_not_nothing(self):
        self._run("suggest", [{"strategy_id": "s1"}], final="error")
        self.assertEqual(ap.status()["runs"]["YouTube"]["result"], "error")

    def test_apply_uses_safe_apply_auto(self):
        calls = []

        def fake_start(sid, auto_target="", **kw):
            calls.append((sid, auto_target))
            sa._write({"session": {"phase": "confirmed", "started": 1}})
            return {"ok": True}
        with mock.patch.object(sa, "start", fake_start), \
                mock.patch.object(sa, "_thread", None), \
                mock.patch.object(ap, "_single_profile_now", lambda: True):
            self._run("apply", [{"strategy_id": "s1", "score": 2}])
        self.assertEqual(calls, [("scan_s1", "YouTube")])
        self.assertEqual(ap.status()["runs"]["YouTube"]["result"],
                         "applied")

    def test_apply_multi_profile_falls_back_to_suggest(self):
        with mock.patch.object(sa, "start") as start, \
                mock.patch.object(ap, "_single_profile_now", lambda: False):
            self._run("apply", [{"strategy_id": "s1", "score": 2}])
        start.assert_not_called()
        self.assertEqual(ap.status()["suggestions"][0]["site"], "YouTube")

    def test_best_prefers_confirmed(self):
        top = ap.best([{"strategy_id": "lucky", "score": 500},
                       {"strategy_id": "solid", "score": 300,
                        "confirmed": True}])
        self.assertEqual(top["strategy_id"], "solid")

    def test_suggestions_per_site(self):
        self._run("suggest", [{"strategy_id": "s1", "score": 2}])
        ap._running["key"] = "Discord"
        sc = FakeScanner([{"strategy_id": "s2", "score": 2}])
        with mock.patch("core.strategy_scanner.get_strategy_scanner",
                        lambda: sc):
            ap._run("Discord", "discord.com", "suggest")
        self.assertEqual({x["site"] for x in ap.status()["suggestions"]},
                         {"YouTube", "Discord"})

    def test_apply_suggestion_and_dismiss(self):
        self._run("suggest", [{"strategy_id": "s1", "score": 2}])
        with mock.patch.object(sa, "start", lambda sid, **kw: {"ok": True}):
            self.assertTrue(ap.apply_suggestion("YouTube")["ok"])
        self.assertEqual(ap.status()["suggestions"], [])
        self.assertFalse(ap.apply_suggestion("YouTube")["ok"])


if __name__ == "__main__":
    unittest.main()
