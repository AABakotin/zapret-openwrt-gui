# tests/test_vpngen.py
"""Генератор конфигов WARP/Proton (core/vpngen): без сети, на подменах.

Что закреплено:
* тела запросов к Cloudflare такие же, как у usque (curve25519 → PATCH
  на secp256r1/masque), а наружу уходят только публичные ключи;
* Proton получает только публичный Ed25519, приватный ключ не покидает
  роутер;
* «авто»-транспорт переходит к следующему обходу только после СЕТЕВОЙ
  ошибки, а ответ API отдаётся сразу;
* у ванильного WireGuard-сервера S1..S4 = 0 и H1..H4 = 1..4 всегда;
* конфиги проходят парсеры своих движков;
* MCP не показывает приватные ключи, а откат удаляет созданное.
"""

import base64
import json
import unittest
from unittest import mock

from core.vpngen import generate as gen
from core.vpngen import keys, net, presets, proton, render, warp

PEER = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="


def _reg():
    return {"id": "dev1", "token": "tok1",
            "account": {"account_type": "free"},
            "config": {"client_id": "AQID",
                       "peers": [{"public_key": PEER, "endpoint": {
                           "v4": "162.159.192.1:0",
                           "v6": "[2606:4700:d0::a29f:c001]:0",
                           "host": "engage.cloudflareclient.com:2408"}}],
                       "interface": {"addresses": {
                           "v4": "172.16.0.2", "v6": "2606:4700:110::2"}}}}


def _masque_reg():
    pem = ("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n"
           % keys.p256_keypair()["public_der_b64"])
    return {"id": "dev1", "token": "tok1",
            "config": {"peers": [{"public_key": pem, "endpoint": {
                "v4": "162.159.198.1:0", "v6": "[2606:4700:103::1]:0"}}],
                "interface": {"addresses": {"v4": "172.16.0.2",
                                            "v6": "2606:4700:110::2"}}}}


class FakeCF:
    """Подмена request_json Cloudflare, записывающая запросы."""

    def __init__(self):
        self.calls = []

    def __call__(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if method == "PATCH":
            return _masque_reg()
        return _reg()


class TestWarpRequests(unittest.TestCase):

    def test_wireguard_registers_real_public_key(self):
        cf = FakeCF()
        with mock.patch.object(warp, "request_json", cf):
            prof = warp.wireguard_native("direct")
        method, url, kw = cf.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/v0a4471/reg"))
        body = kw["body"]
        self.assertEqual(body["key_type"], "curve25519")
        self.assertEqual(body["tunnel_type"], "wireguard")
        self.assertEqual(body["key"],
                         keys.wg_public_from_private(prof["private_key"]))
        self.assertNotIn(prof["private_key"], json.dumps(cf.calls))
        self.assertEqual(prof["endpoint_host"], "engage.cloudflareclient.com")
        self.assertEqual(prof["endpoint_port"], 2408)
        self.assertEqual(prof["reserved"], [1, 2, 3])

    def test_masque_switches_device_like_usque(self):
        cf = FakeCF()
        with mock.patch.object(warp, "request_json", cf):
            prof = warp.masque_native("direct", device_name="router")
        (m1, _u1, _k1), (m2, u2, k2) = cf.calls
        self.assertEqual((m1, m2), ("POST", "PATCH"))
        self.assertTrue(u2.endswith("/reg/dev1"))
        self.assertEqual(k2["body"]["key_type"], "secp256r1")
        self.assertEqual(k2["body"]["tunnel_type"], "masque")
        self.assertEqual(k2["body"]["name"], "router")
        self.assertEqual(k2["headers"]["Authorization"], "Bearer tok1")
        # SPKI публичного ключа уходит, SEC1 приватного — нет.
        self.assertNotIn(prof["private_key"], json.dumps(cf.calls))
        self.assertEqual(prof["endpoint_v4"], "162.159.198.1")
        self.assertEqual(prof["endpoint_v6"], "2606:4700:103::1")
        self.assertEqual(prof["access_token"], "tok1")

    def test_license_failure_is_a_warning(self):
        def fake(method, url, **kw):
            if method == "PUT":
                raise net.GenError("HTTP 400")
            return _reg()
        with mock.patch.object(warp, "request_json", side_effect=fake):
            prof = warp.wireguard_native("direct", license_key="bad")
        self.assertTrue(any("WARP+" in w for w in prof["warnings"]))

    def test_service_mode_marks_third_party_key(self):
        data = {"privKey": "k", "peer_pub": PEER, "client_ipv4": "172.16.0.2",
                "client_ipv6": "2606::2"}
        with mock.patch.object(warp, "request_json", return_value=data):
            prof = warp.wireguard_service("direct")
        self.assertEqual(prof["source"], "service")
        self.assertTrue(any("сервис-генератор" in w for w in prof["warnings"]))


class TestProton(unittest.TestCase):

    def setUp(self):
        proton.reset()

    def test_only_public_key_goes_to_service(self):
        calls = []

        def fake(path, body, transport):
            calls.append((path, body))
            if path.endswith("/session"):
                return {"ok": True, "session": {"uid": "u"}}
            if path.endswith("/servers"):
                return {"ok": True, "servers": [
                    {"id": "1", "name": "NL-FREE#1", "exitCountry": "NL",
                     "city": "Amsterdam", "load": 70,
                     "entryIp": "1.2.3.4", "publicKey": PEER},
                    {"id": "2", "name": "NL-FREE#2", "exitCountry": "NL",
                     "city": "Amsterdam", "load": 10,
                     "entryIp": "1.2.3.5", "publicKey": PEER}]}
            return {"ok": True}
        with mock.patch.object(proton, "_call", side_effect=fake):
            prof = proton.generate("direct", country="NL")
        self.assertEqual(prof["server"]["id"], "2")          # меньше нагрузка
        cert = calls[-1][1]
        self.assertIn("BEGIN PUBLIC KEY", cert["clientPublicKey"])
        self.assertNotIn(prof["private_key"], json.dumps(calls))
        self.assertEqual(prof["ipv4"], "10.2.0.2")

    def test_expired_session_is_reset(self):
        with mock.patch.object(proton, "request_json",
                               return_value={"ok": False,
                                             "error": "Invalid session"}):
            with self.assertRaises(net.GenError):
                proton._call("/api/proton/servers", {}, "direct")
        self.assertIsNone(proton._state["session"])


class TestTransport(unittest.TestCase):

    def test_auto_falls_through_on_network_errors_only(self):
        tried = []

        def fn(t):
            tried.append(t)
            if t == "direct":
                raise net.GenError("timeout", network=True)
            return "ok"
        with mock.patch.object(net, "transports_for",
                               return_value=["direct", "awg:awg0"]):
            res, used, failed = net.run_with_transport("auto", fn)
        self.assertEqual((res, used), ("ok", "awg:awg0"))
        self.assertEqual(len(failed), 1)

    def test_api_error_is_not_retried_elsewhere(self):
        tried = []

        def fn(t):
            tried.append(t)
            raise net.GenError("HTTP 400", status=400)
        with mock.patch.object(net, "transports_for",
                               return_value=["direct", "awg:awg0"]):
            with self.assertRaises(net.GenError):
                net.run_with_transport("auto", fn)
        self.assertEqual(tried, ["direct"])


class TestPresets(unittest.TestCase):

    def test_public_allowed_ips_exclude_lan(self):
        import ipaddress
        nets = [ipaddress.ip_network(n)
                for n in presets.allowed_ips("public", ipv6=False)]
        lan = ipaddress.ip_address("192.168.1.10")
        self.assertFalse(any(lan in n for n in nets))
        self.assertTrue(any(ipaddress.ip_address("8.8.8.8") in n
                            for n in nets))

    def test_dns_without_ipv6(self):
        self.assertEqual(presets.dns_servers("google", ipv6=False),
                         ["8.8.8.8", "8.8.4.4"])
        self.assertEqual(presets.dns_servers("provider", ipv6=True,
                                             provider="proton"),
                         ["10.2.0.1", "2a07:b944::2:1"])

    def test_masks(self):
        q = presets.masks("quic", sni="ozon.ru")["I1"]
        self.assertTrue(q.startswith("<b 0xc"))            # long header
        self.assertGreaterEqual(len(q), 2 * 1200)
        self.assertEqual(set(presets.masks("sip")), {"I1", "I2"})
        self.assertEqual(presets.masks("none"), {})
        self.assertEqual(presets.masks("custom", custom="<r 32>"),
                         {"I1": "<r 32>"})
        with self.assertRaises(ValueError):
            presets.masks("custom", custom="0xdeadbeef")

    def test_dns_mask_encodes_name(self):
        raw = bytes.fromhex(presets.dns_mask("vk.com")[5:-1])
        self.assertIn(b"\x02vk\x03com\x00", raw)


class TestNormalize(unittest.TestCase):

    def test_bad_values_rejected(self):
        for raw in ({"mtu": 900}, {"keepalive": "x"},
                    {"endpoint_mode": "custom", "endpoint": "nohost"},
                    {"junk": {"Jc": 4, "Jmin": 100, "Jmax": 50}},
                    {"awg3": {"RekeyTimeout": "1;rm"}}):
            with self.subTest(raw=raw):
                with self.assertRaises(net.GenError):
                    gen.normalize_options("warp", "wireguard", raw)

    def test_masque_forces_mtu_1280(self):
        with mock.patch.object(gen, "default_sni", return_value="ozon.ru"):
            o = gen.normalize_options("warp", "masque", {"mtu": 1400})
        self.assertEqual(o["mtu"], 1280)
        self.assertEqual(o["sni"], "ozon.ru")


def _wg_profile():
    priv, _ = keys.x25519_keypair()
    return {"provider": "warp", "protocol": "wireguard",
            "private_key": priv, "peer_public_key": PEER,
            "ipv4": "172.16.0.2", "ipv6": "2606:4700:110::2",
            "endpoint_host": "engage.cloudflareclient.com",
            "endpoint_port": 2408, "reserved": [1, 2, 3]}


class TestRender(unittest.TestCase):

    def setUp(self):
        self.opts = gen.normalize_options(
            "warp", "wireguard", {"mask": "sip", "junk": "light"})
        self.opts["label"] = "WARP"

    def test_awg_keeps_vanilla_wireguard_fields(self):
        from core.awg_config import parse_conf, validate
        text = render.awg_conf(_wg_profile(), self.opts)
        cfg = parse_conf(text)
        iface = cfg["interface"]
        self.assertEqual([str(iface[k]) for k in ("S1", "S2")], ["0", "0"])
        self.assertEqual([str(iface["H%d" % i]) for i in range(1, 5)],
                         ["1", "2", "3", "4"])
        self.assertIn("I2", iface)
        self.assertEqual(validate(cfg), [])

    def test_awg_without_obfuscation_is_plain_wireguard(self):
        opts = gen.normalize_options("warp", "wireguard",
                                     {"mask": "none", "junk": "off"})
        text = render.awg_conf(_wg_profile(), opts)
        self.assertNotIn("Jc", text)
        self.assertNotIn("H1", text)

    def test_singbox_uses_endpoints(self):
        from core.singbox_config import parse_conf, validate
        cfg = json.loads(render.singbox_json(_wg_profile(), self.opts))
        self.assertEqual(cfg["endpoints"][0]["type"], "wireguard")
        self.assertFalse(any(o["type"] == "wireguard"
                             for o in cfg["outbounds"]))
        self.assertEqual(cfg["endpoints"][0]["peers"][0]["reserved"],
                         [1, 2, 3])
        self.assertEqual(validate(parse_conf(json.dumps(cfg))), [])

    def test_mihomo_wireguard_with_amnezia_options(self):
        from core.clash_yaml import parse_yaml
        y = parse_yaml(render.mihomo_yaml(_wg_profile(), self.opts))
        p = y["proxies"][0]
        self.assertEqual(p["type"], "wireguard")
        self.assertEqual(p["amnezia-wg-option"]["jc"], 4)
        self.assertIn("i1", p["amnezia-wg-option"])
        self.assertEqual(y["rules"], ["MATCH,WARP-group"])

    def test_mihomo_masque_public_key_is_bare_spki(self):
        from core.clash_yaml import parse_yaml
        with mock.patch.object(warp, "request_json", FakeCF()):
            prof = warp.masque_native("direct")
        y = parse_yaml(render.mihomo_yaml(prof, {"label": "M", "dns": []}))
        self.assertEqual([p.get("network") for p in y["proxies"]],
                         [None, "h2"])
        self.assertNotIn("BEGIN", y["proxies"][0]["public-key"])
        base64.b64decode(y["proxies"][0]["public-key"])
        self.assertEqual(y["proxy-groups"][0]["type"], "fallback")

    def test_usque_json_fields(self):
        with mock.patch.object(warp, "request_json", FakeCF()):
            prof = warp.masque_native("direct")
        data = json.loads(render.usque_json(prof, {}))
        from core.usque_manager import UsqueManager
        self.assertEqual(set(data), set(UsqueManager._USQUE_KNOWN) - {"license"})


class TestGenerate(unittest.TestCase):

    def _run(self, req, saved=True):
        cf = FakeCF()
        with mock.patch.object(warp, "request_json", cf), \
             mock.patch.object(gen, "_existing_names", return_value=set()), \
             mock.patch.object(gen, "_ports_in_configs", return_value=set()), \
             mock.patch.object(gen, "save_output",
                               return_value={"ok": saved, "name": "x"}) as so:
            return gen.generate(req), so

    def test_incompatible_target_rejected(self):
        with self.assertRaises(net.GenError):
            gen.generate({"provider": "warp", "protocol": "masque",
                          "targets": ["singbox"], "transport": "direct"})
        with self.assertRaises(net.GenError):
            gen.generate({"provider": "proton", "targets": ["usque"],
                          "transport": "direct"})

    def test_one_registration_many_targets(self):
        res, so = self._run({"provider": "warp", "protocol": "wireguard",
                             "targets": ["awg", "singbox", "mihomo"],
                             "transport": "direct", "save": True})
        self.assertEqual(set(res["results"]), {"awg", "singbox", "mihomo"})
        self.assertEqual(so.call_count, 3)
        self.assertTrue(res["ok"])
        self.assertTrue(any("одно и то же устройство" in w
                            for w in res["warnings"]))
        ports = {res["results"][t]["listen_port"]
                 for t in ("singbox", "mihomo")}
        self.assertEqual(len(ports), 2)

    def test_save_failure_reported(self):
        res, _ = self._run({"provider": "warp", "targets": ["awg"],
                            "transport": "direct", "save": True},
                           saved=False)
        self.assertFalse(res["ok"])

    def test_mask_hides_keys(self):
        res, _ = self._run({"provider": "warp", "targets": ["awg"],
                            "transport": "direct"})
        text = gen.mask(res["results"]["awg"]["text"], res["secrets"])
        self.assertNotIn(res["secrets"][0], text)
        self.assertIn("«скрыто»", text)


class TestNames(unittest.TestCase):

    def test_unique_and_valid(self):
        self.assertEqual(gen.unique_name("awg", "warp", taken={"warp"}),
                         "warp-2")
        name = gen.unique_name("awg", "proton-very-long-country",
                               taken=set())
        self.assertLessEqual(len(name), 15)
        self.assertTrue(gen.valid_name("awg", name))
        self.assertFalse(gen.valid_name("usque", "a.b"))

    def test_save_output_refuses_existing(self):
        with mock.patch.object(gen, "_existing_names",
                               return_value={"warp"}):
            res = gen.save_output("awg", "warp", "[Interface]\n")
        self.assertFalse(res["ok"])
        self.assertIn("уже есть", res["error"])


    def test_save_output_fails_closed(self):
        # Список не прочитан — не сохраняем (иначе перезапись чужого).
        with mock.patch("core.mihomo_manager.get_mihomo_manager",
                        side_effect=OSError("нет доступа")):
            res = gen.save_output("mihomo", "warp", "proxies: []\n")
        self.assertFalse(res["ok"])
        self.assertIn("не получен", res["error"])

    def test_save_output_reports_os_error(self):
        mgr = mock.Mock()
        mgr.save_config.side_effect = OSError("Read-only file system")
        with mock.patch.object(gen, "_existing_names", return_value=set()), \
             mock.patch("core.awg_manager.get_awg_manager", return_value=mgr):
            res = gen.save_output("awg", "warp", "[Interface]\n")
        self.assertFalse(res["ok"])
        self.assertIn("Read-only", res["error"])


class TestRobustness(unittest.TestCase):

    def test_proton_requires_explicit_ok(self):
        with mock.patch.object(proton, "request_json",
                               return_value={"error": "bad key"}):
            with self.assertRaises(net.GenError):
                proton._call("/api/proton/certificate", {}, "direct")

    def test_proton_load_tolerant(self):
        self.assertEqual(proton._normalize({"load": "12.5"})["load"], 12)
        self.assertEqual(proton._normalize({"load": "N/A"})["load"], 0)

    def test_mihomo_label_with_comma(self):
        opts = gen.normalize_options("warp", "wireguard", {})
        opts["label"] = "My, VPN"
        text = render.mihomo_yaml(_wg_profile(), opts)
        # Имя прокси с запятой допустимо; в правило попадает группа.
        self.assertIn("- MATCH,My VPN\n", text)

    def test_missing_bypass_is_network_error(self):
        with mock.patch("core.download_transport.build_opener",
                        side_effect=RuntimeError("интерфейс не найден")):
            with self.assertRaises(net.GenError) as cm:
                net._opener("awg:gone")
        self.assertTrue(cm.exception.network)

    def test_post_not_retried(self):
        opener = mock.Mock()
        opener.open.side_effect = TimeoutError("timed out")
        with mock.patch.object(net, "_opener", return_value=opener), \
             mock.patch.object(net.time, "sleep"):
            with self.assertRaises(net.GenError):
                net.request_json("POST", "https://x.example/reg", body={})
        self.assertEqual(opener.open.call_count, 1)


class TestMcpTool(unittest.TestCase):

    def test_generate_masks_keys_and_records_undo(self):
        from core.mcp.tools import vpngen as tool
        fake = {"ok": True, "results": {"awg": {
                    "name": "warp", "saved": True,
                    "text": "PrivateKey = SECRET\n"}},
                "secrets": ["SECRET"], "warnings": []}
        with mock.patch.object(gen, "generate", return_value=fake), \
             mock.patch.object(tool.audit, "snapshot",
                               return_value={"id": "s1"}) as snap:
            out = tool.vpngen_generate({"provider": "warp"})
        self.assertNotIn("SECRET", json.dumps(out))
        self.assertEqual(snap.call_args.args[3],
                         [{"target": "awg", "name": "warp"}])

    def test_undo_deletes_created(self):
        from core.mcp.tools import vpngen as tool
        with mock.patch.object(gen, "delete_output",
                               return_value={"ok": True}) as d:
            out = tool._undo_generated(
                {"after": [{"target": "awg", "name": "warp"}]})
        self.assertTrue(out["ok"])
        d.assert_called_once_with("awg", "warp")


class TestApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from tests._wsgi_client import WSGIClient, build_test_app
        cls.client = WSGIClient(build_test_app())

    def test_options(self):
        r = self.client.get_json("/api/vpngen/options")
        self.assertTrue(r["ok"])
        self.assertEqual({t["id"] for t in r["targets"]},
                         {"awg", "usque", "singbox", "mihomo"})

    def test_bad_transport_rejected(self):
        r = self.client.post_json("/api/vpngen/generate",
                                  {"provider": "warp", "transport": "ftp:x"})
        self.assertFalse(r["ok"])

    def test_generate_hides_secret_list(self):
        fake = {"ok": True, "results": {}, "secrets": ["S"]}
        with mock.patch("core.vpngen.generate.generate", return_value=fake):
            r = self.client.post_json("/api/vpngen/generate",
                                      {"provider": "warp"})
        self.assertNotIn("secrets", r)

    def test_save_validates_target(self):
        r = self.client.post_json("/api/vpngen/save",
                                  {"target": "evil", "name": "x", "text": "y"})
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
