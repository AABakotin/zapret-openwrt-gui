# tests/test_help_report.py
"""«Отчёт для помощи»: без секретов, внешнего адреса и (по умолчанию) сайтов."""

import unittest
from unittest import mock

from core import help_report


class TestHelpReport(unittest.TestCase):

    def _build(self, show_sites=False):
        rows = ["- arg --hostlist-domains=rutracker.org",
                "- wan 93.184.216.34, lan 192.168.1.1",
                "- auth_password=hunter2 token: abc123secret"]
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

    def test_secrets_redacted(self):
        text = self._build(show_sites=True)
        self.assertNotIn("hunter2", text)
        self.assertNotIn("abc123secret", text)

    def test_broken_section_does_not_break_report(self):
        with mock.patch.object(help_report, "_lists",
                               side_effect=RuntimeError("boom")):
            text = help_report.build()["text"]
        self.assertIn("### Версии", text)


if __name__ == "__main__":
    unittest.main()
