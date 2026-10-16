# tests/test_help_report.py
"""«Отчёт для помощи»: без секретов, внешнего адреса и (по умолчанию) сайтов."""

import unittest
from unittest import mock

from core import help_report


class TestHelpReport(unittest.TestCase):

    def _build(self, show_sites=False):
        rows = ["- arg --hostlist-domains=rutracker.org",
                "- wan 93.184.216.34, lan 192.168.1.1"]
        with mock.patch.object(help_report, "_nfqws", return_value=rows):
            return help_report.build(show_sites=show_sites)["text"]

    def test_sections_present(self):
        text = self._build()
        for title in ("### Версии", "### Обход DPI", "### Конфликты"):
            self.assertIn(title, text)

    def test_sites_masked_by_default(self):
        text = self._build()
        self.assertNotIn("rutracker.org", text)
        self.assertIn("<домен-1>", text)

    def test_sites_shown_on_request_but_ip_masked(self):
        text = self._build(show_sites=True)
        self.assertIn("rutracker.org", text)
        self.assertNotIn("93.184.216.34", text)
        self.assertIn("192.168.1.1", text)

    def test_secrets_redacted_in_free_text(self):
        out = help_report._free_text(
            "--auth_password=hunter2 token: abc123secret")
        self.assertNotIn("hunter2", out)
        self.assertNotIn("abc123secret", out)

    def test_broken_section_says_so(self):
        with mock.patch.object(help_report, "_conflicts",
                               side_effect=RuntimeError("boom")):
            text = help_report.build()["text"]
        self.assertIn("### Версии", text)
        self.assertIn("не удалось собрать: RuntimeError", text)
        self.assertNotIn("- нет", text.split("### Конфликты")[1][:40])

    def test_versions_not_masked(self):
        from core.mcp import issues
        with mock.patch.object(issues, "_engines", return_value=[
                {"name": "singbox", "current": "1.12.4.1"},
                {"name": "gui", "current": "0.1"}]):
            text = help_report.build()["text"]
        self.assertIn("singbox: 1.12.4.1", text)
        self.assertNotIn("- gui: 0.1", text)

    def test_list_named_like_secret_keeps_count(self):
        with mock.patch.object(help_report, "_lists",
                               return_value=["- token: 120 записей, обход"]):
            text = help_report.build(show_sites=True)["text"]
        self.assertIn("token: 120 записей", text)

    def test_url_path_cut_in_log(self):
        from core.log_buffer import get_log_buffer
        with mock.patch.object(get_log_buffer(), "get_filtered", return_value=[
                {"date": "d", "time": "t", "level": "WARNING", "source": "x",
                 "message": "Ошибка загрузки URL https://h.example/s/AbCdEf123secret"}]):
            text = help_report.build(show_sites=True)["text"]
        self.assertNotIn("AbCdEf123secret", text)

    def test_both_variants_from_one_collect(self):
        with mock.patch.object(help_report, "collect",
                               wraps=help_report.collect) as col:
            both = help_report.build_both()
        self.assertEqual(col.call_count, 1)
        self.assertIn("masked", both)
        self.assertIn("sites", both)


if __name__ == "__main__":
    unittest.main()
