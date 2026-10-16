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
    def __init__(self, working):
        self.working = working
        self.started = None

    def start(self, **kw):
        self.started = kw
        return True

    def get_status(self):
        return {"status": "completed"}

    def get_working_strategies(self):
        return self.working

    def save_working_by_id(self, sid):
        return {"id": "scan_" + sid, "name": "[Scan] " + sid}


class TestRun(Case):

    def _run(self, mode, working):
        sc = FakeScanner(working)
        with mock.patch("core.strategy_scanner.get_strategy_scanner",
                        lambda: sc):
            ap._running["key"] = "YouTube"
            ap._run("YouTube", "youtube.com", mode)
        return sc

    def test_trigger_off_does_nothing(self):
        self.cfg.set("healthcheck", "autopick", {"mode": "off"})
        self.assertFalse(ap.trigger("YouTube", ["youtube.com"])["ok"])

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
        st = ap.status()
        self.assertEqual(st["suggestion"]["strategy_id"], "scan_s1")
        self.assertEqual(st["runs"]["YouTube"]["result"], "suggested")
        self.assertIsNone(st["running"])
        self.assertTrue(self.notes)

    def test_nothing_found(self):
        self._run("suggest", [])
        self.assertEqual(ap.status()["runs"]["YouTube"]["result"], "nothing")
        self.assertIsNone(ap.status()["suggestion"])

    def test_apply_uses_safe_apply_auto(self):
        calls = []
        with mock.patch.object(sa, "start", lambda sid, auto_target="",
                               **kw: calls.append((sid, auto_target))
                               or {"ok": True}):
            self._run("apply", [{"strategy_id": "s1", "score": 2}])
        self.assertEqual(calls, [("scan_s1", "YouTube")])
        self.assertEqual(ap.status()["runs"]["YouTube"]["result"],
                         "applying")

    def test_apply_suggestion_and_dismiss(self):
        self._run("suggest", [{"strategy_id": "s1", "score": 2}])
        with mock.patch.object(sa, "start", lambda sid, **kw: {"ok": True}):
            self.assertTrue(ap.apply_suggestion()["ok"])
        self.assertIsNone(ap.status()["suggestion"])
        self.assertFalse(ap.apply_suggestion()["ok"])


if __name__ == "__main__":
    unittest.main()
