# tests/test_diagnostics_rivals.py
"""Другие обходчики DPI рядом с nfqws2 (core/diagnostics.evaluate_rival_bypassers)."""

import unittest
from unittest import mock

from core import diagnostics as diag
from core.diagnostics import evaluate_rival_bypassers


class TestEvaluateRivals(unittest.TestCase):

    def test_none(self):
        self.assertEqual(evaluate_rival_bypassers(set(), set()), [])

    def test_process(self):
        r = evaluate_rival_bypassers({"youtubeUnblock"}, set())
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["id"], "rival-youtubeunblock")
        self.assertEqual(r[0]["severity"], "error")
        self.assertIn("youtubeUnblock", r[0]["title"])
        self.assertIn("Процесс", r[0]["detail"])
        self.assertIn("через раз", r[0]["hint"])

    def test_kernel_module(self):
        r = evaluate_rival_bypassers(set(), {"kyoutubeUnblock"})
        self.assertEqual(len(r), 1)
        self.assertIn("модуль ядра", r[0]["detail"])

    def test_one_entry_per_tool(self):
        # byedpi бывает под двумя именами — запись одна.
        r = evaluate_rival_bypassers({"ciadpi", "byedpi"}, set())
        self.assertEqual(len(r), 1)

    def test_unrelated_processes_ignored(self):
        self.assertEqual(
            evaluate_rival_bypassers({"nfqws2", "dnsmasq", "sing-box"},
                                     set()), [])

    def test_known_conflicts_puts_rivals_first(self):
        with mock.patch.object(diag, "_running_process_names",
                               side_effect=lambda w: {"b4"} & set(w)), \
             mock.patch.object(diag, "_loaded_kernel_modules",
                               return_value=set()), \
             mock.patch.object(diag, "_existing_foreign_markers",
                               return_value=set()), \
             mock.patch.object(diag, "_foreign_autostart_script",
                               return_value=None), \
             mock.patch("os.path.exists", return_value=False):
            res = diag.check_known_conflicts()
        self.assertTrue(res["has_conflicts"])
        self.assertEqual(res["warnings"][0]["id"], "rival-b4")


if __name__ == "__main__":
    unittest.main()
