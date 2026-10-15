# tests/test_warp_in_warp_masque.py
"""MASQUE-стороны WARP-in-WARP: транспорт inner и границы с usque-watchdog."""

import unittest
from unittest import mock

from core import warp_in_warp as wiw


class TestMasqueMasque(unittest.TestCase):

    def test_inner_always_goes_over_h2(self):
        """TUN outer'а у usque — 1280: H3-датаграмма inner с пакетом в 1280
        байт в него не помещается, поэтому inner обязан идти по H2/TCP."""
        mgr = mock.Mock()
        mgr.iface_for_config.side_effect = ["usque0", "usque1"]
        mgr.start.return_value = {"ok": True,
                                  "transport_profile": "performance"}
        m = wiw.WarpInWarpManager()
        with mock.patch("core.usque_manager.get_usque_manager",
                        return_value=mgr), \
             mock.patch.object(wiw, "_resolve_host",
                               return_value=("162.159.198.2", None)), \
             mock.patch.object(wiw, "_pin_route_owned",
                               return_value=(True, "")), \
             mock.patch.object(m, "_apply_optimizations"):
            r = m._start_masque_masque("", "", "/c/outer.conf",
                                       "/c/inner.conf", "162.159.198.2",
                                       "performance")
        self.assertTrue(r["ok"], r)
        outer_call, inner_call = mgr.start.call_args_list
        self.assertEqual(outer_call.kwargs["transport_profile"], "performance")
        self.assertEqual(inner_call.kwargs["transport_profile"], "restricted")
        self.assertEqual(r["inner_transport_profile"], "restricted")


class TestUsqueIfaces(unittest.TestCase):

    def _mgr(self, mode, outer, inner):
        m = wiw.WarpInWarpManager()
        m._mode, m._outer_iface, m._inner_iface = mode, outer, inner
        return m

    def test_only_usque_sides_reported(self):
        self.assertEqual(
            self._mgr("masque_masque", "usque0", "usque1").usque_ifaces(),
            {"usque0", "usque1"})
        self.assertEqual(
            self._mgr("masque_awg", "usque0", "awg0").usque_ifaces(),
            {"usque0"})
        self.assertEqual(
            self._mgr("awg_masque", "awg0", "usque1").usque_ifaces(),
            {"usque1"})

    def test_nothing_when_stopped(self):
        with mock.patch.object(wiw, "_load_runtime", return_value={}):
            self.assertEqual(wiw.WarpInWarpManager().usque_ifaces(),
                             frozenset())


if __name__ == "__main__":
    unittest.main()
