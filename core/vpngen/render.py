# core/vpngen/render.py
"""
Профиль (WARP/Proton, WireGuard/MASQUE) → текст конфига нужного движка.

Чистые функции, без сети и диска: на вход профиль от ``warp``/``proton``
и нормализованные опции генератора, на выход — строка ровно того
формата, который движок читает сам:

* AmneziaWG — ``.conf`` (через ``core.awg_config.render_conf``, тот же
  рендер, что у редактора конфигов);
* usque — ``config.json`` с полями из ``config/config.go`` апстрима;
* sing-box — JSON с WireGuard **в ``endpoints``** (в ``outbounds`` тип
  ``wireguard`` удалён в 1.13). MASQUE sing-box не умеет;
* mihomo — YAML; WireGuard с ``amnezia-wg-option`` (mihomo умеет
  AmneziaWG-обфускацию прямо в прокси), MASQUE — ``type: masque``
  (поля сверены с ``adapter/outbound/masque.go`` v1.19.32).

Опции (см. ``core.vpngen.generate.normalize_options``):
    dns, mtu, keepalive, allowed, ipv6, endpoint_host/port,
    junk{Jc,Jmin,Jmax}, masks{I1..I5}, awg3{...}, sni, listen_port, label
"""

from __future__ import annotations

import json

from core.vpngen import keys

SINGBOX_TAG = "proxy-out"


def _addresses(profile: dict, ipv6: bool) -> list:
    out = []
    if profile.get("ipv4"):
        out.append("%s/32" % profile["ipv4"].split("/")[0])
    if ipv6 and profile.get("ipv6"):
        out.append("%s/128" % profile["ipv6"].split("/")[0])
    return out


def _endpoint(profile: dict, opts: dict) -> tuple:
    host = opts.get("endpoint_host") or profile.get("endpoint_host")
    port = int(opts.get("endpoint_port") or profile.get("endpoint_port")
               or 2408)
    return host, port


# ─────────────────────────────── AmneziaWG ───────────────────────────

def awg_conf(profile: dict, opts: dict) -> str:
    from core.awg_config import render_conf

    iface = {
        "PrivateKey": profile["private_key"],
        "Address": _addresses(profile, opts.get("ipv6", True)),
        "DNS": list(opts.get("dns") or []),
        "MTU": int(opts.get("mtu") or 1280),
    }
    junk = opts.get("junk") or {}
    if int(junk.get("Jc") or 0) > 0 or opts.get("masks"):
        # Сервер — ванильный WireGuard: S1..S4 = 0 и H1..H4 = 1..4
        # обязательны (core/vpngen/presets.py, скил awg §8.1).
        iface.update({"Jc": int(junk.get("Jc") or 0),
                      "Jmin": int(junk.get("Jmin") or 0),
                      "Jmax": int(junk.get("Jmax") or 0),
                      "S1": 0, "S2": 0,
                      "H1": 1, "H2": 2, "H3": 3, "H4": 4})
    for key, value in (opts.get("masks") or {}).items():
        iface[key] = value
    for key, value in (opts.get("awg3") or {}).items():
        if value not in ("", None):
            iface[key] = value

    host, port = _endpoint(profile, opts)
    peer = {
        "PublicKey": profile["peer_public_key"],
        "AllowedIPs": list(opts.get("allowed") or ["0.0.0.0/0"]),
        "Endpoint": "%s:%d" % (("[%s]" % host) if ":" in host else host,
                               port),
    }
    if int(opts.get("keepalive") or 0) > 0:
        peer["PersistentKeepalive"] = int(opts["keepalive"])
    return render_conf({"interface": iface, "peers": [peer]})


# ─────────────────────────────── usque ───────────────────────────────

def usque_json(profile: dict, opts: dict) -> str:
    data = {
        "private_key": profile["private_key"],
        "endpoint_v4": profile.get("endpoint_v4") or "",
        "endpoint_v6": profile.get("endpoint_v6") or "",
        # Как у `usque register`: H2-эндпоинт — зашитый дефолт апстрима
        # (config.DefaultEndpointH2V4), v6 для H2 у consumer-WARP пуст.
        "endpoint_h2_v4": "162.159.198.2",
        "endpoint_h2_v6": "",
        "endpoint_pub_key": profile["endpoint_pub_key"],
        "id": profile.get("id") or "",
        "access_token": profile.get("access_token") or "",
        "ipv4": profile.get("ipv4") or "",
        "ipv6": profile.get("ipv6") or "",
    }
    return json.dumps(data, indent=2) + "\n"


# ─────────────────────────────── sing-box ────────────────────────────

def singbox_endpoint(profile: dict, opts: dict, *,
                     tag: str = SINGBOX_TAG) -> dict:
    """WireGuard-endpoint sing-box (1.11+) для профиля."""
    host, port = _endpoint(profile, opts)
    peer = {
        "address": host,
        "port": port,
        "public_key": profile["peer_public_key"],
        "allowed_ips": list(opts.get("allowed") or ["0.0.0.0/0"]),
    }
    if int(opts.get("keepalive") or 0) > 0:
        peer["persistent_keepalive_interval"] = int(opts["keepalive"])
    if profile.get("reserved"):
        peer["reserved"] = list(profile["reserved"])
    ep = {
        "type": "wireguard",
        "tag": tag,
        "mtu": int(opts.get("mtu") or 1280),
        "address": _addresses(profile, opts.get("ipv6", True)),
        "private_key": profile["private_key"],
        "peers": [peer],
    }
    if not _is_ip(host):
        # Имя сервера (engage.cloudflareclient.com) резолвим напрямую:
        # через сам туннель его не узнать — туннеля ещё нет.
        ep["domain_resolver"] = "dns-local"
    return ep


def singbox_json(profile: dict, opts: dict) -> str:
    """Самостоятельный конфиг: локальный mixed-порт → WireGuard.

    DNS клиентов резолвится через туннель (DoH 1.1.1.1 поверх endpoint) —
    иначе подменённые провайдером ответы для заблокированных сайтов
    уводили бы соединения не туда. Формат DNS — sing-box 1.12+ (typed);
    мы ставим 1.14.
    """
    cfg = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"type": "https", "tag": "dns-remote", "server": "1.1.1.1",
                 "detour": SINGBOX_TAG},
                {"type": "local", "tag": "dns-local"},
            ],
            "final": "dns-remote",
        },
        "inbounds": [{
            "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
            "listen_port": int(opts.get("listen_port") or 1080),
        }],
        "endpoints": [singbox_endpoint(profile, opts)],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [{"inbound": ["mixed-in"], "action": "sniff"},
                      {"ip_is_private": True, "outbound": "direct"}],
            "final": SINGBOX_TAG,
            "default_domain_resolver": "dns-remote",
        },
    }
    return json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"


def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(str(host).strip("[]"))
        return True
    except ValueError:
        return False


# ─────────────────────────────── mihomo ──────────────────────────────

def mihomo_proxies(profile: dict, opts: dict) -> list:
    """Прокси mihomo для профиля (MASQUE — два: H3 и H2 запасной)."""
    label = opts.get("label") or "VPN"
    dns = list(opts.get("dns") or ["1.1.1.1"])
    if profile.get("protocol") == "masque":
        base = {
            "type": "masque",
            "server": profile.get("endpoint_v4") or "162.159.198.2",
            "port": 443,
            "private-key": profile["private_key"],
            # mihomo ждёт голый base64 SPKI, а Cloudflare/usque — PEM.
            "public-key": keys.pem_body(profile["endpoint_pub_key"]),
            "ip": profile.get("ipv4") or "",
            "mtu": 1280,
            "udp": True,
            "remote-dns-resolve": True,
            "dns": dns,
        }
        if opts.get("ipv6", True) and profile.get("ipv6"):
            base["ipv6"] = profile["ipv6"]
        if opts.get("sni"):
            base["sni"] = opts["sni"]
        h3 = dict(base, name="%s (H3)" % label)
        h2 = dict(base, name="%s (H2)" % label, network="h2")
        return [h3, h2]

    host, port = _endpoint(profile, opts)
    proxy = {
        "name": label,
        "type": "wireguard",
        "server": host,
        "port": port,
        "ip": profile["ipv4"],
        "private-key": profile["private_key"],
        "public-key": profile["peer_public_key"],
        "allowed-ips": list(opts.get("allowed") or ["0.0.0.0/0"]),
        "udp": True,
        "mtu": int(opts.get("mtu") or 1280),
        "remote-dns-resolve": True,
        "dns": dns,
    }
    if opts.get("ipv6", True) and profile.get("ipv6"):
        proxy["ipv6"] = profile["ipv6"]
    if profile.get("reserved"):
        proxy["reserved"] = list(profile["reserved"])
    if int(opts.get("keepalive") or 0) > 0:
        proxy["persistent-keepalive"] = int(opts["keepalive"])
    awg = {}
    junk = opts.get("junk") or {}
    if int(junk.get("Jc") or 0) > 0:
        awg.update({"jc": int(junk["Jc"]), "jmin": int(junk.get("Jmin") or 0),
                    "jmax": int(junk.get("Jmax") or 0)})
    for key, value in (opts.get("masks") or {}).items():
        awg[key.lower()] = value
    _AWG3_YAML = {"ContentPaddingAddition": "content-padding-addition",
                  "RekeyAfterTime": "rekey-after-time",
                  "RekeyTimeout": "rekey-timeout",
                  "RejectAfterTime": "reject-after-time",
                  "KeepaliveTimeout": "keepalive-timeout",
                  "MaxHandshakeAttempts": "max-handshake-attempts"}
    for key, value in (opts.get("awg3") or {}).items():
        if value not in ("", None) and key in _AWG3_YAML:
            awg[_AWG3_YAML[key]] = str(value)
    if awg:
        if any(k in awg for k in _AWG3_YAML.values()):
            awg["version"] = 3
        proxy["amnezia-wg-option"] = awg
    return [proxy]


def mihomo_yaml(profile: dict, opts: dict) -> str:
    """Самостоятельный конфиг mihomo: mixed-порт на localhost → прокси."""
    from core.clash_yaml import dump_yaml

    proxies = mihomo_proxies(profile, opts)
    names = [p["name"] for p in proxies]
    group = {"name": opts.get("label") or "VPN", "proxies": names}
    if len(names) > 1:
        # MASQUE: H3, а если UDP режут — сам переключится на H2.
        group.update(type="fallback",
                     url="https://www.gstatic.com/generate_204",
                     interval=300)
    else:
        group["type"] = "select"
    if group["name"] in names:
        group["name"] = "%s-group" % group["name"]
    cfg = {
        "mixed-port": int(opts.get("listen_port") or 7890),
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "info",
        "ipv6": bool(opts.get("ipv6", True)),
        "proxies": proxies,
        "proxy-groups": [group],
        "rules": ["MATCH,%s" % group["name"]],
    }
    return dump_yaml(cfg)
