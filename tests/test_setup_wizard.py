# tests/test_setup_wizard.py
"""Мастер настройки (core/setup_wizard): план, TUN-конфиги, apply.

Закреплено:
* метод маршрута — тот, что понимает единый слой: awg:<name>,
  warp:<iface usque>, singbox:/mihomo:<tun>;
* «все устройства» — устройства поштучно и без адресов самого роутера
  (подсеть LAN захватила бы ответы роутера);
* WireGuard в sing-box уходит в endpoints, несколько прокси — urltest;
* перехват DNS включается только в режимах «устройства»/«все»;
* провал шага останавливает мастер и честно отчитывается.
"""

import json
import unittest
from unittest import mock

from core import setup_wizard as sw


def _plan(**kw):
    plan = {"engine": "awg",
            "source": {"kind": "generate", "generate": {"provider": "warp"}},
            "route": {"mode": "sites", "services": ["youtube"]},
            "transport": "direct", "autostart": False}
    plan.update(kw)
    return plan


class TestValidate(unittest.TestCase):

    def test_errors(self):
        cases = [
            _plan(engine="nope"),
            _plan(source={"kind": "link"}),                 # не для AWG
            _plan(route={"mode": "sites"}),                 # пусто
            _plan(route={"mode": "devices", "devices": ["not-ip"]}),
            _plan(route={"mode": "sites", "domains": ["bad domain!"]}),
        ]
        for plan in cases:
            with self.subTest(plan=plan):
                with self.assertRaises(sw.WizardError):
                    sw.validate_plan(plan)

    def test_services_to_geosite(self):
        dest = sw._destination({"services": ["telegram", "ai"],
                                "domains": ["https://Example.com/path"]})
        self.assertIn("telegram", dest["geosite"])
        self.assertIn("openai", dest["geosite"])
        self.assertEqual(dest["geoip"], ["telegram"])
        self.assertEqual(dest["domains"], ["example.com"])


class TestDevices(unittest.TestCase):

    def test_all_devices_exclude_router_itself(self):
        found = [{"ip": "192.168.1.1", "mac": "a", "hostname": "router"},
                 {"ip": "192.168.1.50", "mac": "b", "hostname": "tv"}]
        with mock.patch("core.devices_discovery.list_devices",
                        return_value=found), \
             mock.patch.object(sw, "_own_addresses",
                               return_value={"192.168.1.1"}):
            devs = sw._devices({}, "all")
        self.assertEqual([d["ip"] for d in devs], ["192.168.1.50"])

    def test_router_itself_rejected_as_device(self):
        with mock.patch.object(sw, "_own_addresses",
                               return_value={"192.168.1.1"}):
            for ip in ("192.168.1.1", "127.0.0.1", "0.0.0.0", "224.0.0.1"):
                with self.subTest(ip=ip):
                    with self.assertRaises(sw.WizardError):
                        sw._devices({"devices": [ip]}, "devices")

    def test_wan_neighbours_excluded(self):
        found = [{"ip": "192.168.0.1", "mac": "m", "iface": "eth0"},
                 {"ip": "192.168.1.50", "mac": "b", "iface": "br0"}]
        with mock.patch("core.devices_discovery.list_devices",
                        return_value=found), \
             mock.patch.object(sw, "_own_addresses", return_value=set()), \
             mock.patch.object(sw, "_wan_ifaces", return_value={"eth0"}):
            self.assertEqual([d["ip"] for d in sw.devices()],
                             ["192.168.1.50"])

    def test_default_route_on_lan_keeps_devices(self):
        # Точка доступа / роутер за роутером: маршрут по умолчанию через
        # мост LAN — фильтр «стороны провайдера» не должен выкинуть всех.
        found = [{"ip": "192.168.1.50", "mac": "b", "iface": "br0"}]
        with mock.patch("core.devices_discovery.list_devices",
                        return_value=found), \
             mock.patch.object(sw, "_own_addresses", return_value=set()), \
             mock.patch.object(sw, "_wan_ifaces", return_value={"br0"}):
            self.assertEqual([d["ip"] for d in sw.devices()],
                             ["192.168.1.50"])

    def test_unknown_list_rejected(self):
        with mock.patch.object(sw, "_known_list_ids", return_value={"a"}):
            self.assertEqual(sw._destination({"list_ids": ["a"]})["list_ids"],
                             ["a"])
            with self.assertRaises(sw.WizardError):
                sw._destination({"list_ids": ["gone"]})

    def test_all_without_devices_fails(self):
        with mock.patch.object(sw, "devices", return_value=[]):
            with self.assertRaises(sw.WizardError):
                sw._devices({}, "all")


class TestTunConfigs(unittest.TestCase):

    def test_singbox_wireguard_goes_to_endpoints(self):
        ep = {"type": "wireguard", "tag": "x", "domain_resolver": "dns-x",
              "address": ["172.16.0.2/32"], "private_key": "k",
              "peers": [{"address": "1.1.1.1", "port": 2408,
                         "public_key": "p", "allowed_ips": ["0.0.0.0/0"]}]}
        cfg = sw.singbox_tun_config([ep], "sbtun0", hijack_dns=False)
        self.assertEqual(cfg["endpoints"][0]["tag"], "proxy-out")
        self.assertEqual(cfg["endpoints"][0]["domain_resolver"], "dns-local")
        self.assertEqual(cfg["inbounds"][0]["interface_name"], "sbtun0")
        self.assertFalse(cfg["inbounds"][0]["auto_route"])
        self.assertFalse(any(r.get("action") == "hijack-dns"
                             for r in cfg["route"]["rules"]))
        self.assertEqual(cfg["route"]["final"], "proxy-out")

    def test_singbox_many_proxies_urltest_and_hijack(self):
        obs = [{"type": "vless", "server": "a", "server_port": 443},
               {"type": "trojan", "server": "b", "server_port": 443}]
        cfg = sw.singbox_tun_config(obs, "sbtun1", hijack_dns=True)
        ut = [o for o in cfg["outbounds"] if o["type"] == "urltest"][0]
        self.assertEqual(ut["tag"], "proxy-out")
        self.assertEqual(ut["outbounds"], ["proxy-1", "proxy-2"])
        self.assertTrue(any(r.get("action") == "hijack-dns"
                            for r in cfg["route"]["rules"]))
        from core.singbox_config import parse_conf, validate
        self.assertEqual(validate(parse_conf(json.dumps(cfg))), [])

    def test_mihomo_tun_no_auto_route(self):
        proxies = [{"name": "A", "type": "ss"}]
        cfg = sw.mihomo_tun_config(proxies, "mhtun0", hijack_dns=False)
        self.assertFalse(cfg["tun"]["auto-route"])
        self.assertEqual(cfg["tun"]["dns-hijack"], [])
        self.assertNotIn("dns", cfg)
        cfg = sw.mihomo_tun_config(proxies * 2, "mhtun0", hijack_dns=True)
        self.assertEqual(cfg["tun"]["dns-hijack"], ["any:53"])
        self.assertEqual(cfg["proxy-groups"][0]["type"], "url-test")

    def test_mihomo_unique_names_and_lan_direct(self):
        proxies = [{"name": "A", "type": "ss"}, {"name": "A", "type": "ss"}]
        cfg = sw.mihomo_tun_config(proxies, "mhtun0", hijack_dns=True)
        self.assertEqual([p["name"] for p in cfg["proxies"]], ["A", "A (2)"])
        self.assertEqual(cfg["proxy-groups"][0]["proxies"], ["A", "A (2)"])
        self.assertIn("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", cfg["rules"])
        self.assertEqual(cfg["rules"][-1], "MATCH,VPN")
        self.assertEqual(proxies[1]["name"], "A")      # вход не тронут

    def test_mihomo_clash_yaml_subscription(self):
        text = ("proxies:\n"
                "  - {name: one, type: ss, server: a.example, port: 443,"
                " cipher: aes-128-gcm, password: x}\n")
        out = sw._mihomo_proxies_from_links(text, "direct")
        self.assertEqual(out[0]["name"], "one")

    def test_pick_tun(self):
        self.assertEqual(sw.pick_tun("sbtun", {"sbtun0", "sbtun1"}), "sbtun2")


class TestApply(unittest.TestCase):

    def _apply(self, plan, *, up=None, route=None):
        up = up or {"ok": True}
        route = route or {"ok": True, "route": {"id": "r1"},
                          "applied": {"skipped_selectors": []}}
        gen_res = {"ok": True, "warnings": [], "results": {
            plan["engine"]: {"saved": True, "name": "warp"}}}
        with mock.patch("core.vpngen.generate.generate",
                        return_value=gen_res) as g, \
             mock.patch("core.tunnels_control.up", return_value=up) as u, \
             mock.patch("core.unified.manager.save_route",
                        return_value=route) as sr:
            res = sw.apply(plan)
        return res, g, u, sr

    def test_awg_generate_route(self):
        res, g, u, sr = self._apply(_plan())
        self.assertTrue(res["ok"], res)
        self.assertEqual(g.call_args.args[0]["targets"], ["awg"])
        u.assert_called_once_with("awg", "warp")
        doc = sr.call_args.args[0]
        self.assertEqual(doc["method"], "awg:warp")
        self.assertIn("youtube", doc["destination"]["geosite"])
        self.assertEqual([s["step"] for s in res["steps"]],
                         ["config", "start", "route"])

    def test_usque_uses_warp_method_and_masque(self):
        res, g, _u, sr = self._apply(
            _plan(engine="usque"), up={"ok": True, "iface": "usque3"})
        req = g.call_args.args[0]
        self.assertEqual((req["provider"], req["protocol"]),
                         ("warp", "masque"))
        self.assertEqual(sr.call_args.args[0]["method"], "warp:usque3")

    def test_proton_import_passes_config(self):
        plan = _plan(source={"kind": "generate", "generate": {
            "provider": "proton", "source": "import", "config": "[Peer]"}})
        res, g, _u, _sr = self._apply(plan)
        self.assertTrue(res["ok"], res)
        req = g.call_args.args[0]
        self.assertEqual((req["source"], req["config"]), ("import", "[Peer]"))

    def test_start_failure_stops(self):
        res, _g, _u, sr = self._apply(
            _plan(), up={"ok": False, "error": "TUN нет"})
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "TUN нет")
        sr.assert_not_called()

    def test_none_mode_skips_route(self):
        res, _g, _u, sr = self._apply(_plan(route={"mode": "none"}))
        self.assertTrue(res["ok"])
        sr.assert_not_called()

    def test_singbox_link_builds_tun_config(self):
        saved = {}

        def fake_save(engine, name, cfg):
            saved.update(engine=engine, name=name, cfg=cfg)
            return {"ok": True}
        plan = _plan(engine="singbox",
                     source={"kind": "link",
                             "link": "vless://11111111-2222-3333-4444-"
                                     "555555555555@example.com:443"
                                     "?security=tls&sni=example.com#a"},
                     route={"mode": "devices",
                            "devices": ["192.168.1.50"]})
        with mock.patch.object(sw, "_save_engine_config",
                               side_effect=fake_save), \
             mock.patch.object(sw, "_taken_tun_names", return_value=set()), \
             mock.patch("core.vpngen.generate._existing_names",
                        return_value=set()), \
             mock.patch("core.tunnels_control.up",
                        return_value={"ok": True}), \
             mock.patch("core.unified.manager.save_route",
                        return_value={"ok": True, "route": {"id": "r"}}) as sr:
            res = sw.apply(plan)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["iface"], "sbtun0")
        self.assertEqual(sr.call_args.args[0]["method"], "singbox:sbtun0")
        self.assertEqual(sr.call_args.args[0]["devices"][0]["ip"],
                         "192.168.1.50")
        self.assertTrue(any(r.get("action") == "hijack-dns"
                            for r in saved["cfg"]["route"]["rules"]))

    def test_masque_rejected_for_singbox(self):
        plan = _plan(engine="singbox", source={
            "kind": "generate",
            "generate": {"provider": "warp", "protocol": "masque"}})
        res = sw.apply(plan)
        self.assertFalse(res["ok"])
        self.assertIn("MASQUE", res["error"])


class TestApplyGuards(unittest.TestCase):

    _apply = TestApply._apply

    def test_route_saved_but_not_applied_is_failure(self):
        res, _g, _u, _sr = self._apply(_plan(), route={
            "ok": True, "route": {"id": "r1"},
            "applied": {"ok": False, "error": "ipset отказал"}})
        self.assertFalse(res["ok"])
        self.assertIn("ipset отказал", res["error"])
        self.assertFalse(res["steps"][-1]["ok"])
        # Туннель и маршрут уже есть — UI не предлагает повтор с нуля.
        self.assertTrue(res["partial"])
        self.assertEqual(res["route_id"], "r1")

    def test_apply_error_from_derived_rules(self):
        self.assertEqual(sw.apply_error({"ok": False, "applied": [
            {"ok": True}, {"ok": False, "deferred": True},
            {"ok": False, "error": "нет ipset"}]}), "нет ipset")

    def test_concurrent_apply_rejected(self):
        self.assertTrue(sw._apply_lock.acquire(blocking=False))
        try:
            res = sw.apply(_plan())
        finally:
            sw._apply_lock.release()
        self.assertFalse(res["ok"])
        self.assertIn("уже выполняется", res["error"])

    def test_usque_existing_running_is_not_started_again(self):
        plan = _plan(engine="usque", source={"kind": "existing",
                                             "name": "warp"})
        with mock.patch.object(sw, "_configs", return_value=["warp"]), \
             mock.patch.object(sw, "_usque_running_iface",
                               return_value="usque1"), \
             mock.patch("core.tunnels_control.up") as up, \
             mock.patch("core.unified.manager.save_route",
                        return_value={"ok": True, "route": {"id": "r"}}) as sr:
            res = sw.apply(plan)
        self.assertTrue(res["ok"], res)
        up.assert_not_called()
        self.assertEqual(sr.call_args.args[0]["method"], "warp:usque1")

    def test_all_devices_without_devices_reports_error(self):
        with mock.patch.object(sw, "devices", return_value=[]):
            res = sw.apply(_plan(route={"mode": "all"}))
        self.assertFalse(res["ok"])
        self.assertEqual(res["steps"], [])


class TestApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from tests._wsgi_client import WSGIClient, build_test_app
        cls.client = WSGIClient(build_test_app())

    def test_options(self):
        r = self.client.get_json("/api/setup-wizard/options")
        self.assertTrue(r["ok"])
        self.assertEqual({e["id"] for e in r["engines"]},
                         {"awg", "usque", "singbox", "mihomo"})
        self.assertTrue(r["services"])

    def test_install_rejects_unknown(self):
        r = self.client.post_json("/api/setup-wizard/install",
                                  {"engine": "rm -rf"})
        self.assertFalse(r["ok"])

    def test_apply_validation_error(self):
        r = self.client.post_json("/api/setup-wizard/apply", {"engine": "x"})
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
