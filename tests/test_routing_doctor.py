# tests/test_routing_doctor.py
"""
Routing doctor — пошаговая диагностика «правило есть, а трафик мимо
туннеля» (core/routing/doctor). Проверяем разбор вывода утилит и сборку
отчёта по здоровой/сломанной цепочке.
"""

import unittest
from unittest import mock

from core.routing import doctor
from core.routing.rules import DomainRoutingRule


class TestParsers(unittest.TestCase):

    def test_ipset_count_parses_header(self):
        out = ("Name: awgr_x\nType: hash:ip\nNumber of entries: 42\n"
               "Members:\n1.2.3.4\n")
        with mock.patch.object(doctor, "_run",
                               return_value=(0, out, "")):
            self.assertEqual(doctor._ipset_count("awgr_x"), 42)

    def test_ipset_count_missing_set(self):
        with mock.patch.object(doctor, "_run",
                               return_value=(1, "", "does not exist")):
            self.assertIsNone(doctor._ipset_count("nope"))

    def test_has_fwmark_rule_hex(self):
        lines = ["0:\tfrom all lookup local",
                 "10100:\tfrom all fwmark 0x1abcd lookup 361",
                 "32766:\tfrom all lookup main"]
        with mock.patch.object(doctor, "_ip_rule_lines",
                               return_value=lines):
            self.assertTrue(doctor._has_fwmark_rule(0x1abcd, 361))
            self.assertFalse(doctor._has_fwmark_rule(0x1abcd, 999))

    def test_mangle_counters(self):
        out = ("Chain AWG_ROUTING_PRE (1 references)\n"
               "    pkts      bytes target     prot opt in     out\n"
               "     123     4567 MARK       all  --  *      *       "
               "0.0.0.0/0  0.0.0.0/0  match-set awgr_x dst MARK set 0x1abcd\n")
        with mock.patch.object(doctor, "_run",
                               return_value=(0, out, "")):
            found, pkts = doctor._mangle_mark_counters("awgr_x")
        self.assertTrue(found)
        # обе цепочки (PRE и OUT) вернули одинаковый мок → 123*2
        self.assertEqual(pkts, 246)

    def test_route_get_dev(self):
        out = "1.2.3.4 dev WARPv1_61 table 361 src 172.16.0.2\n"
        with mock.patch.object(doctor, "_run",
                               return_value=(0, out, "")):
            self.assertEqual(doctor._route_get_dev("1.2.3.4", mark=7),
                             "WARPv1_61")


class TestDiagnose(unittest.TestCase):

    def _rule(self):
        return DomainRoutingRule(target_iface="awg0",
                                 domains=["example.com"],
                                 rule_id="uni-doc")

    def _patch_chain(self, healthy=True):
        from core.routing import domain_rule
        return [
            mock.patch("core.routing.storage.load_rules",
                       return_value=[self._rule()]),
            mock.patch.object(domain_rule, "_sets_state_load",
                              return_value={"uni-doc": "ipset"}),
            mock.patch.object(domain_rule, "_iproute_state_load",
                              return_value={}),
            mock.patch.object(domain_rule, "_iface_exists",
                              return_value=True),
            mock.patch.object(domain_rule, "_resolve_ips",
                              return_value=["1.2.3.4"]),
            mock.patch.object(doctor, "_ipset_count", return_value=10),
            mock.patch.object(doctor, "_mangle_mark_counters",
                              return_value=(True, 5 if healthy else 0)),
            mock.patch.object(doctor, "_has_fwmark_rule",
                              return_value=True),
            mock.patch.object(doctor, "_table_default_iface",
                              return_value="awg0"),
            mock.patch.object(doctor, "_masquerade_present",
                              return_value=True),
            mock.patch.object(doctor, "_ipset_test", return_value=True),
            mock.patch.object(doctor, "_route_get_dev",
                              return_value="awg0" if healthy else "eth0"),
            mock.patch.object(doctor, "_run",
                              return_value=(0, "", "")),
        ]

    def _run_diag(self, healthy):
        patches = self._patch_chain(healthy)
        for p in patches:
            p.start()
        try:
            return doctor.diagnose()
        finally:
            for p in patches:
                p.stop()

    def test_healthy_chain_all_ok(self):
        report = self._run_diag(healthy=True)
        self.assertTrue(report["ok"], doctor.render_text(report))
        self.assertEqual(len(report["rules"]), 1)

    def test_broken_chain_flags_failures(self):
        report = self._run_diag(healthy=False)
        self.assertFalse(report["ok"])
        bad = [c["name"] for c in report["rules"][0]["checks"]
               if not c["ok"]]
        # 0 пакетов на mark-правиле и route get мимо туннеля — оба видны
        self.assertTrue(any("маркировка" in n for n in bad), bad)
        self.assertTrue(any("route get" in n for n in bad), bad)

    def test_render_text_smoke(self):
        report = self._run_diag(healthy=True)
        text = doctor.render_text(report)
        self.assertIn("uni-doc", text)
        self.assertIn("✓", text)


class TestSingboxTun(unittest.TestCase):
    """Звено «внутри sing-box»: конфиг с TUN запущен и стек пропустит TCP
    (issue #386: system без auto_route — Telegram «не открывается»)."""

    def _cfg(self, inbounds):
        import json
        import os
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            if isinstance(inbounds, str):
                f.write(inbounds)
            else:
                json.dump({"inbounds": inbounds, "outbounds": []}, f)
        self.addCleanup(os.unlink, path)
        return path

    def _checks(self, tun, running=True, iface="singbox-tun"):
        configs = [
            {"name": "other", "path": "/nope", "running": True,
             "tun_iface": ""},
            {"name": "vless", "path": self._cfg([tun]), "running": running,
             "tun_iface": "singbox-tun"}]
        return doctor._singbox_tun_checks(iface, configs)

    def test_gvisor_running_ok(self):
        checks = self._checks({"type": "tun", "stack": "gvisor",
                               "interface_name": "singbox-tun"})
        self.assertTrue(all(c["ok"] for c in checks), checks)

    def test_system_without_auto_route_flagged(self):
        checks = self._checks({"type": "tun", "stack": "system",
                               "interface_name": "singbox-tun"})
        bad = [c for c in checks if not c["ok"]]
        self.assertEqual(len(bad), 1, checks)
        self.assertIn("gvisor", bad[0]["details"])

    def test_default_stack_is_mixed_and_flagged(self):
        checks = self._checks({"type": "tun",
                               "interface_name": "singbox-tun"})
        self.assertTrue(any(not c["ok"] and "mixed" in c["name"]
                            for c in checks), checks)

    def test_system_with_auto_route_ok(self):
        checks = self._checks({"type": "tun", "stack": "system",
                               "auto_route": True,
                               "interface_name": "singbox-tun"})
        self.assertTrue(all(c["ok"] for c in checks), checks)

    def test_stopped_config_flagged(self):
        checks = self._checks({"type": "tun", "stack": "gvisor",
                               "interface_name": "singbox-tun"},
                              running=False)
        self.assertFalse(checks[0]["ok"])

    def test_no_config_for_iface(self):
        checks = self._checks({"type": "tun", "stack": "gvisor",
                               "interface_name": "singbox-tun"},
                              iface="tun9")
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0]["ok"])

    def test_running_config_preferred_over_stopped(self):
        # У всех конфигов по умолчанию singbox-tun: остановленный не должен
        # заслонять запущенный.
        tun = {"type": "tun", "stack": "gvisor"}
        configs = [
            {"name": "a", "path": self._cfg([dict(tun, stack="system")]),
             "running": False, "tun_iface": "singbox-tun"},
            {"name": "b", "path": self._cfg([tun]), "running": True,
             "tun_iface": "singbox-tun"}]
        checks = doctor._singbox_tun_checks("singbox-tun", configs)
        self.assertTrue(all(c["ok"] for c in checks), checks)
        self.assertIn("«b»", checks[0]["name"])

    def test_second_tun_inbound_matched_by_name(self):
        path = self._cfg([
            {"type": "tun", "interface_name": "tun0", "stack": "gvisor"},
            {"type": "tun", "interface_name": "tun1", "stack": "system"}])
        configs = [{"name": "two", "path": path, "running": True,
                    "tun_iface": "tun0"}]
        bad = [c for c in doctor._singbox_tun_checks("tun1", configs)
               if not c["ok"]]
        self.assertEqual(len(bad), 1)
        self.assertIn("system", bad[0]["name"])

    def test_broken_json_flagged(self):
        configs = [{"name": "bad", "path": self._cfg("{not json"),
                    "running": True, "tun_iface": "singbox-tun"}]
        checks = doctor._singbox_tun_checks("singbox-tun", configs)
        self.assertFalse(all(c["ok"] for c in checks), checks)

if __name__ == "__main__":
    unittest.main()
