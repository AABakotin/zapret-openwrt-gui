# tests/test_dashboard_brief.py
"""«Кратко» на главной (core/dashboard_brief): уровни и строки из ответа
/api/dashboard/status."""

import unittest

from core.dashboard_brief import brief


def data(**kw):
    st = {"nfqws": {"running": True},
          "strategy": {"id": "s1", "name": "YouTube"},
          "autostart": {"enabled": True},
          "zapret": {"installed": True, "version": "0.9"}}
    st.update(kw.pop("status", {}))
    out = {"status": st, "rivals": [], "healthcheck": {}}
    out.update(kw)
    return out


def hc(results, outage=False):
    ok = sum(1 for r in results if r["ok"])
    return {"enabled": True, "history": [{
        "total": len(results), "ok": ok, "global_outage": outage,
        "results": results}]}


class TestBrief(unittest.TestCase):

    def test_all_good(self):
        b = brief(data(healthcheck=hc([{"display": "YouTube", "ok": True}])))
        self.assertEqual(b["level"], "ok")
        self.assertTrue(b["line"].startswith("Всё работает"))
        self.assertIn("YouTube", b["line"])
        self.assertIn("открываются все 1", b["line"])

    def test_stopped_with_strategy_is_bad(self):
        b = brief(data(status={"nfqws": {"running": False, "exit_code": 1}}))
        self.assertEqual(b["level"], "bad")
        self.assertIn("код выхода 1", b["line"])
        self.assertEqual(b["blocks"]["nfqws"]["level"], "bad")
        self.assertEqual(b["problems"][0]["page"], "control")

    def test_no_strategy_is_warn(self):
        b = brief(data(status={"nfqws": {"running": False},
                               "strategy": {"id": None, "name": ""}}))
        self.assertEqual(b["level"], "warn")
        self.assertIn("стратегия не выбрана", b["line"])

    def test_autostart_off_is_warn(self):
        b = brief(data(status={"autostart": {"enabled": False}}))
        self.assertEqual(b["level"], "warn")
        self.assertTrue(b["line"].startswith("Работает, но"))

    def test_rival_is_bad(self):
        b = brief(data(rivals=[{"name": "byedpi"}]))
        self.assertEqual(b["level"], "bad")
        self.assertIn("byedpi", b["line"])

    def test_failed_sites_open_monitoring(self):
        b = brief(data(healthcheck=hc([
            {"display": "A", "ok": False}, {"display": "B", "ok": False},
            {"display": "C", "ok": False}, {"display": "D", "ok": False},
            {"display": "E", "ok": True}])))
        self.assertEqual(b["blocks"]["monitoring"]["level"], "bad")
        self.assertEqual(b["blocks"]["monitoring"]["text"],
                         "открываются 1 из 5")
        self.assertIn("A, B, C и ещё 1", b["line"])

    def test_global_outage(self):
        b = brief(data(healthcheck=hc([{"display": "A", "ok": False}],
                                      outage=True)))
        self.assertIn("ни один", b["line"])

    def test_vpn_summary(self):
        b = brief(data(awg={"total": 2, "active": 1, "names": ["wg0"]},
                       opera={"running": True}))
        self.assertEqual(b["blocks"]["vpn"]["text"],
                         "подняты: AmneziaWG (wg0), Opera Proxy")
        self.assertEqual(b["blocks"]["vpn"]["level"], "ok")
        b = brief(data(awg={"total": 1, "active": 0}))
        self.assertEqual(b["blocks"]["vpn"]["text"], "туннели не подняты")

    def test_empty_input(self):
        b = brief({})
        self.assertIn(b["level"], ("ok", "warn", "bad"))


if __name__ == "__main__":
    unittest.main()
