# tests/test_usque_watchdog.py
"""Watchdog usque: повторы после неудачного рестарта, WARP-in-WARP, auto."""

import unittest
from unittest import mock

from core import usque_watchdog as uw


class _FakeCfg:
    def __init__(self, **usque):
        self._usque = usque

    def get(self, *path, default=None):
        node = {"usque": self._usque}
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node


class _FakeMgr:
    """Минимальный UsqueManager: один профиль warp на usque0."""

    def __init__(self, start_results):
        self.active = True
        self.seq = 0
        self.start_results = list(start_results)
        self.started = []

    def list_configs(self):
        return [{"name": "warp", "path": "/cfg/warp.conf", "iface": "usque0",
                 "active": self.active}]

    def stop(self, iface):
        self.active = False
        self.seq += 1
        return {"ok": True}

    def stop_seq(self, iface):
        return self.seq

    def start(self, iface, path, sni="", transport_profile="performance"):
        self.started.append(transport_profile)
        res = self.start_results.pop(0)
        if res.get("ok"):
            self.active = True
        return res


class TestUsqueWatchdog(unittest.TestCase):

    def setUp(self):
        self.wd = uw.UsqueWatchdog()
        self.wd._stop_evt = mock.Mock()
        patches = [
            mock.patch("core.config_manager.get_config_manager",
                       return_value=_FakeCfg(transport_profile="auto")),
            mock.patch.object(uw, "_warp_in_warp_ifaces",
                              return_value=frozenset()),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _expire_cooldown(self):
        for k in self.wd._last_restart:
            self.wd._last_restart[k] -= uw._DEFAULT_COOLDOWN_SEC + 1

    def test_failed_restart_is_retried_until_up(self):
        """Раньше туннель после неудачного рестарта лежал навсегда:
        _tick() проверяет только активные, а этот уже не активен."""
        mgr = _FakeMgr([{"ok": False, "error": "boom"}, {"ok": True}])
        self.wd._do_restart(mgr, "usque0", "warp")
        self.assertIn("usque0", self.wd._pending)

        self.wd._retry_pending(mgr, mgr.list_configs())   # cooldown
        self.assertEqual(len(mgr.started), 1)

        self._expire_cooldown()
        self.wd._retry_pending(mgr, mgr.list_configs())
        self.assertEqual(len(mgr.started), 2)
        self.assertTrue(mgr.active)
        self.assertNotIn("usque0", self.wd._pending)

    def test_manual_stop_cancels_retries(self):
        mgr = _FakeMgr([{"ok": False, "error": "boom"}])
        self.wd._do_restart(mgr, "usque0", "warp")
        mgr.stop("usque0")        # пользователь нажал «Стоп»
        self._expire_cooldown()
        self.wd._retry_pending(mgr, mgr.list_configs())
        self.assertEqual(len(mgr.started), 1)
        self.assertNotIn("usque0", self.wd._pending)

    def test_auto_alternates_transport(self):
        """auto больше не застревает на H2 навсегда."""
        mgr = _FakeMgr([{"ok": True}, {"ok": True}, {"ok": True}])
        for _ in range(3):
            self.wd._do_restart(mgr, "usque0", "warp")
        self.assertEqual(mgr.started,
                         ["restricted", "performance", "restricted"])

    def test_warp_in_warp_tunnels_are_left_alone(self):
        mgr = _FakeMgr([])
        self.wd._fail_counts["usque0"] = uw._DEFAULT_CONSECUTIVE_FAILURES
        with mock.patch.object(uw, "_warp_in_warp_ifaces",
                               return_value=frozenset({"usque0"})), \
             mock.patch.object(uw, "_probe_via_iface") as probe, \
             mock.patch("core.usque_manager.get_usque_manager",
                        return_value=mgr):
            self.wd._tick()
        probe.assert_not_called()
        self.assertEqual(mgr.seq, 0)

    def test_interval_clamped(self):
        self.assertEqual(uw._clamp_interval("abc"),
                         uw._DEFAULT_CHECK_INTERVAL)
        self.assertEqual(uw._clamp_interval(0), 10)
        self.assertEqual(uw._clamp_interval(10 ** 6), 3600)
        self.assertEqual(uw._clamp_interval("30"), 30)


if __name__ == "__main__":
    unittest.main()
