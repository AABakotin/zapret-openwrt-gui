# core/setup_wizard.py
"""
Мастер настройки VPN по шагам — бэкенд одной кнопки «Запустить».

Пользователь отвечает на четыре вопроса (страница «Мастер настройки»):

1. **Какая программа** — AmneziaWG, WARP/MASQUE (usque), sing-box, mihomo;
2. **Откуда сервер** — бесплатный WARP/Proton из генератора
   (``core.vpngen``), ссылка/подписка (sing-box, mihomo), готовый конфиг
   текстом (AWG, usque) или конфиг, который уже есть;
3. **Что пускать через VPN** — выбранные сервисы/сайты, всё с выбранных
   устройств, всё со всех найденных устройств или ничего (сам настрою);
4. **Запуск** — эта функция: ``apply(plan)``.

``apply`` делает ровно то, что пользователь иначе собирал бы на четырёх
страницах, и отчитывается по шагам (``steps``), останавливаясь на первом
провале:

* ``config``    — сохранить конфиг (для sing-box/mihomo — собрать НОВЫЙ с
  TUN-интерфейсом, потому что маршрутизацию единого слоя движок получает
  через свой TUN);
* ``start``     — поднять инстанс (``core.tunnels_control.up``);
* ``autostart`` — включить запуск после перезагрузки (не фатально);
* ``route``     — маршрут единого слоя «назначение → <движок>:<iface>»
  (``core.unified.manager.save_route``), тот же, что на странице
  «Маршрутизация».

Почему маршрут через единый слой, а не собственные билдеры sing-box/
mihomo: так у всех четырёх движков одна модель («сайты → туннель»),
маршрут виден и правится на общей странице, а failover/мониторинг уже
есть.

«Все устройства» — это найденные сейчас устройства ПОШТУЧНО, а не
подсеть LAN: правило «from 192.168.1.0/24» захватило бы и ответы самого
роутера (его адрес в той же подсети), и веб-интерфейс стал бы
недоступен из LAN.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import urllib.error

from core.log_buffer import log

ENGINES = {
    "awg": {"label": "AmneziaWG", "method": "awg",
            "sources": ("generate", "paste", "existing")},
    "usque": {"label": "WARP/MASQUE (usque)", "method": "warp",
              "sources": ("generate", "paste", "existing")},
    "singbox": {"label": "sing-box", "method": "singbox",
                "sources": ("generate", "link", "existing")},
    "mihomo": {"label": "mihomo", "method": "mihomo",
               "sources": ("generate", "link", "existing")},
}

# Сервисы для шага «что пускать». geosite/geoip — категории v2fly: их
# разворачивает единый слой (для AWG/usque/mihomo — в домены и CIDR через
# dnsmasq+ipset, sing-box понимает их сам).
SERVICES = [
    {"id": "youtube", "label": "YouTube", "geosite": ["youtube"]},
    {"id": "instagram", "label": "Instagram и Facebook",
     "geosite": ["instagram", "facebook"]},
    {"id": "telegram", "label": "Telegram", "geosite": ["telegram"],
     "geoip": ["telegram"]},
    {"id": "discord", "label": "Discord", "geosite": ["discord"]},
    {"id": "ai", "label": "ChatGPT, Claude, Gemini",
     "geosite": ["openai", "anthropic", "google-gemini"]},
    {"id": "twitter", "label": "X (Twitter)", "geosite": ["twitter"]},
    {"id": "tiktok", "label": "TikTok", "geosite": ["tiktok"]},
    {"id": "netflix", "label": "Netflix", "geosite": ["netflix"]},
    {"id": "spotify", "label": "Spotify", "geosite": ["spotify"]},
    {"id": "twitch", "label": "Twitch", "geosite": ["twitch"]},
    {"id": "reddit", "label": "Reddit", "geosite": ["reddit"]},
    {"id": "linkedin", "label": "LinkedIn", "geosite": ["linkedin"]},
]

ROUTE_MODES = ("sites", "devices", "all", "none")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")


class WizardError(RuntimeError):
    pass


# ───────────────────────────── что есть ──────────────────────────────

def _platform() -> dict:
    try:
        from core.awg_detector import get_awg_detector
        plat = get_awg_detector().detect_platform().as_dict()
        return {"tun_available": bool(plat.get("tun_available")),
                "tun_instructions": plat.get("tun_instructions") or ""}
    except Exception:                                # noqa: BLE001
        return {"tun_available": True, "tun_instructions": ""}


def _configs(engine: str) -> list:
    from core.vpngen.generate import _existing_names
    return sorted(n for n in _existing_names(engine) if n)


def options() -> dict:
    from core.vpngen import generate as gen
    installed = gen._installed()
    lists = []
    try:
        from core import named_lists
        lists = [{"id": l.get("id"), "name": l.get("name"),
                  "domains": l.get("domain_count", 0),
                  "cidrs": l.get("cidr_count", 0)}
                 for l in named_lists.list_all() if l.get("id")]
    except Exception:                                # noqa: BLE001
        pass
    return {
        "ok": True,
        "engines": [dict(id=k, label=v["label"], sources=list(v["sources"]),
                         installed=installed.get(k, False),
                         configs=_configs(k))
                    for k, v in ENGINES.items()],
        "services": SERVICES,
        "lists": lists,
        "platform": _platform(),
        "transports": gen._transport_list(),
    }


def devices() -> list:
    """Устройства LAN для шага «по устройствам» (без самого роутера)."""
    try:
        from core.devices_discovery import list_devices
        items = list_devices() or []
    except Exception:                                # noqa: BLE001
        return []
    own = _own_addresses()
    wan = _wan_ifaces()
    out, wan_side = [], []
    for d in items:
        ip = str(d.get("ip") or "").strip()
        if not ip or ip in own:
            continue
        # Соседи со стороны провайдера (шлюз, модем) — не устройства LAN:
        # «все устройства» не должны завернуть в VPN и их.
        item = {"ip": ip, "mac": d.get("mac") or "",
                "hostname": d.get("hostname") or d.get("name") or ""}
        if d.get("iface") and d.get("iface") in wan:
            wan_side.append(item)
            continue
        out.append(item)
    # Маршрут по умолчанию идёт через сам мост LAN (точка доступа, роутер
    # за роутером, ПК с одной сетевой картой) — тогда «сторона провайдера»
    # и есть LAN, и фильтр выкинул бы всех.
    return out or wan_side


def _wan_ifaces() -> set:
    """Интерфейсы маршрутов по умолчанию (сторона провайдера)."""
    out = set()
    try:
        import subprocess
        for fam in ("-4", "-6"):
            r = subprocess.run(["ip", fam, "route", "show", "default"],
                               capture_output=True, text=True, timeout=5)
            out.update(re.findall(r"\bdev\s+(\S+)", r.stdout or ""))
    except Exception:                                # noqa: BLE001
        pass
    return out


def _own_addresses() -> set:
    out = set()
    try:
        import subprocess
        r = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True,
                           text=True, timeout=5)
        for m in re.finditer(r"inet6?\s+([0-9a-fA-F:.]+)/", r.stdout or ""):
            out.add(m.group(1))
    except Exception:                                # noqa: BLE001
        pass
    return out


# ───────────────────────────── установка ─────────────────────────────

_install_lock = threading.Lock()
_install_state = {}


def start_install(engine: str, transport: str = "") -> dict:
    """Поставить движок в фоне. Статус — ``install_status(engine)``."""
    if engine not in ENGINES:
        return {"ok": False, "error": "неизвестная программа"}
    with _install_lock:
        st = _install_state.get(engine) or {}
        if st.get("running"):
            return {"ok": True, "running": True}
        _install_state[engine] = {"running": True, "ok": None,
                                  "message": "Скачиваю…"}

    def _run():
        try:
            res = _do_install(engine, transport)
        except Exception as e:                       # noqa: BLE001
            res = {"ok": False, "error": str(e)}
        with _install_lock:
            _install_state[engine] = {
                "running": False, "ok": bool(res.get("ok")),
                "message": (res.get("error") or res.get("message")
                            or ("Установлено" if res.get("ok")
                                else "Не установлено"))}
        log.info("мастер: установка %s — %s" % (
            engine, "ок" if res.get("ok") else res.get("error")),
            source="setup_wizard")

    threading.Thread(target=_run, daemon=True,
                     name="wizard-install-%s" % engine).start()
    return {"ok": True, "running": True}


def _do_install(engine: str, transport: str) -> dict:
    if engine == "singbox":
        from core.singbox_installer import get_singbox_installer
        return get_singbox_installer().install(transport=transport)
    if engine == "mihomo":
        from core.mihomo_installer import get_mihomo_installer
        return get_mihomo_installer().install(transport=transport)
    if engine == "awg":
        from core.awg_installer import get_awg_installer
        return get_awg_installer().install_binaries(transport=transport)
    from core.ext_binary_installer import install_binary_by_name
    res = install_binary_by_name("usque", transport=transport)
    if res.get("ok"):
        tag = str(res.get("tag") or res.get("version") or "").strip()
        if tag:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            cfg.set("usque", "installed_tag", tag)
            cfg.save()
    return res


def install_status(engine: str) -> dict:
    from core.vpngen import generate as gen
    with _install_lock:
        st = dict(_install_state.get(engine) or {})
    st["installed"] = bool(gen._installed().get(engine))
    st.setdefault("running", False)
    return dict(st, ok=True, engine=engine,
                result=st.get("ok"))


# ─────────────────────────── прокси из источника ─────────────────────

def _fetch_subscription(url: str, transport: str) -> str:
    """Скачать подписку; «авто» — напрямую, при сетевой ошибке через обход."""
    from core.download_transport import urlopen_via
    from core.vpngen.net import GenError, run_with_transport

    def fetch(t):
        try:
            with urlopen_via(url, transport=t, timeout=30) as resp:
                return resp.read(2 * 1024 * 1024).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            # Сервер ответил — другой транспорт не поможет.
            raise GenError("HTTP %s" % e.code)
        except Exception as e:                       # noqa: BLE001
            raise GenError(str(e), network=True)
    try:
        text, _used, _tried = run_with_transport(transport or "auto", fetch)
    except GenError as e:
        raise WizardError("подписка не скачалась: %s" % e)
    return text


def _source_text(text: str, transport: str) -> str:
    """Текст ссылок/подписки; URL подписки скачивается."""
    text = (text or "").strip()
    if re.match(r"^https?://\S+$", text):
        text = _fetch_subscription(text, transport)
    return text


def _uris(text: str) -> list:
    from core.subscription_importer import extract_items
    return [it["value"] for it in extract_items(text)
            if it.get("type") == "uri" and it.get("value")]


def _singbox_proxies_from_links(text: str, transport: str) -> list:
    from core.singbox_subscription import uri_to_outbound
    out = []
    for uri in _uris(_source_text(text, transport)):
        r = uri_to_outbound(uri)
        if r.get("ok") and r.get("outbound"):
            out.append(dict(r["outbound"]))
    if not out:
        raise WizardError("в ссылке/подписке нет поддерживаемых прокси"
                          " (vless, vmess, trojan, ss, hysteria2, tuic)")
    return out


def _mihomo_proxies_from_links(text: str, transport: str) -> list:
    from core.clash_yaml import parse_yaml, uri_to_clash_proxy
    text = _source_text(text, transport)
    out = []
    # Подписка для mihomo обычно — clash-YAML с `proxies:`, а не ссылки.
    if re.search(r"^proxies\s*:", text, re.M):
        from core import mihomo_proxies as mp
        try:
            out = [dict(p) for p in mp.list_proxies(parse_yaml(text) or {})]
        except Exception:                            # noqa: BLE001
            out = []
    for uri in ([] if out else _uris(text)):
        r = uri_to_clash_proxy(uri)
        if r.get("ok") and r.get("proxy"):
            out.append(dict(r["proxy"]))
    if not out:
        raise WizardError("в ссылке/подписке нет поддерживаемых прокси")
    return out


_NON_PROXY = ("direct", "block", "dns", "selector", "urltest")


def _singbox_proxies_from_config(name: str) -> list:
    from core import tunnels_control
    text = tunnels_control.config_get("singbox", name).get("text") or "{}"
    cfg = json.loads(text)
    out = [dict(ob) for ob in cfg.get("outbounds") or []
           if isinstance(ob, dict) and ob.get("type") not in _NON_PROXY
           and ob.get("server")]
    out += [dict(ep) for ep in cfg.get("endpoints") or []
            if isinstance(ep, dict) and ep.get("type") == "wireguard"]
    if not out:
        raise WizardError("в конфиге «%s» нет прокси-серверов" % name)
    return out


def _mihomo_proxies_from_config(name: str) -> list:
    from core import tunnels_control
    from core.clash_yaml import parse_yaml
    from core import mihomo_proxies as mp
    text = tunnels_control.config_get("mihomo", name).get("text") or ""
    out = [dict(p) for p in mp.list_proxies(parse_yaml(text) or {})]
    if not out:
        raise WizardError("в конфиге «%s» нет прокси" % name)
    return out


def _generated_proxies(engine: str, gen_req: dict, transport: str) -> tuple:
    """(proxies, profile) из генератора — без сохранения конфига-прокси."""
    from core.vpngen import generate as gen
    from core.vpngen import render
    from core.vpngen.net import run_with_transport, GenError

    provider = str(gen_req.get("provider") or "warp")
    protocol = str(gen_req.get("protocol") or "wireguard")
    if engine == "singbox" and protocol == "masque":
        raise WizardError("sing-box не умеет MASQUE — выберите WireGuard")
    source = str(gen_req.get("source") or
                 gen.PROVIDERS.get(provider, {}).get("sources",
                                                     ("native",))[0])
    try:
        opts = gen.normalize_options(provider, protocol,
                                     gen_req.get("options") or {})
        profile, _used, _tried = run_with_transport(
            transport, lambda t: gen._profile(provider, protocol, source,
                                              t, gen_req))
    except GenError as e:
        raise WizardError(str(e))
    opts["label"] = gen._label(profile, opts)
    if engine == "singbox":
        return [render.singbox_endpoint(profile, opts)], profile
    return render.mihomo_proxies(profile, opts), profile


# ─────────────────────────── сборка TUN-конфигов ─────────────────────

def _taken_tun_names() -> set:
    names = set()
    try:
        names.update(os.listdir("/sys/class/net"))
    except OSError:
        pass
    from core import tunnels_control
    for engine in ("singbox", "mihomo"):
        for name in _configs(engine):
            try:
                text = tunnels_control.config_get(engine, name).get("text")
            except Exception:                        # noqa: BLE001
                continue
            names.update(re.findall(
                r'"interface_name"\s*:\s*"([^"]+)"', text or ""))
            names.update(re.findall(r"^\s*device\s*:\s*['\"]?([\w.\-]+)",
                                    text or "", re.M))
    return names


def pick_tun(prefix: str, taken=None) -> str:
    taken = set(taken if taken is not None else _taken_tun_names())
    for n in range(0, 100):
        name = "%s%d" % (prefix, n)
        if name not in taken:
            return name
    raise WizardError("не найдено свободного имени TUN-интерфейса")


def singbox_tun_config(proxies: list, tun: str, *, hijack_dns: bool,
                       subnet_index: int = 0) -> dict:
    """sing-box с TUN (без auto_route) → прокси; маршрут решает единый слой.

    WireGuard уходит в ``endpoints`` (в ``outbounds`` он удалён в 1.13).
    Несколько прокси — urltest «proxy-out»: sing-box сам берёт быстрый.
    """
    from core.singbox_config import make_tun_inbound, _TUN_TAG

    outbounds, endpoints, tags = [], [], []
    many = len(proxies) > 1
    for i, item in enumerate(proxies, 1):
        item = dict(item)
        item["tag"] = "proxy-%d" % i if many else "proxy-out"
        tags.append(item["tag"])
        (endpoints if item.get("type") == "wireguard"
         else outbounds).append(item)
    if many:
        outbounds.append({"type": "urltest", "tag": "proxy-out",
                          "outbounds": tags,
                          "url": "https://www.gstatic.com/generate_204",
                          "interval": "5m"})
    for ep in endpoints:
        # domain_resolver в WG-endpoint ссылается на DNS-сервер генератора.
        if ep.get("domain_resolver"):
            ep["domain_resolver"] = "dns-local"
    outbounds.append({"type": "direct", "tag": "direct"})
    rules = [{"inbound": [_TUN_TAG], "action": "sniff"}]
    if hijack_dns:
        rules.append({"protocol": "dns", "action": "hijack-dns"})
    rules.append({"ip_is_private": True, "outbound": "direct"})
    cfg = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"type": "https", "tag": "dns-remote", "server": "1.1.1.1",
                 "detour": "proxy-out"},
                {"type": "local", "tag": "dns-local"},
            ],
            "final": "dns-remote",
        },
        "inbounds": [make_tun_inbound(
            interface_name=tun,
            address=["172.19.%d.1/30" % (subnet_index % 250)],
            mtu=1400, stack="gvisor", auto_route=False)],
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "proxy-out",
                  "default_domain_resolver": "dns-local"},
    }
    if endpoints:
        cfg["endpoints"] = endpoints
    return cfg


def mihomo_tun_config(proxies: list, tun: str, *, hijack_dns: bool,
                      group_type: str = "select") -> dict:
    """mihomo с TUN (auto-route выключен) → группа прокси."""
    from core import mihomo_config as mc

    stack = "gvisor"
    try:
        from core.mihomo_detector import get_mihomo_detector
        if not get_mihomo_detector().detect_binary().get("has_gvisor", True):
            stack = "system"
    except Exception:                                # noqa: BLE001
        pass
    tun_cfg = mc.make_tun(device=tun, stack=stack, mtu=1400,
                          auto_route=False)
    tun_cfg["dns-hijack"] = ["any:53"] if hijack_dns else []
    # mihomo отвергает конфиг с повторяющимися именами прокси, а в
    # подписках они повторяются часто — нумеруем дубли.
    proxies = [dict(p) for p in proxies]
    seen = set()
    for p in proxies:
        base = str(p.get("name") or "proxy")
        name, n = base, 2
        while name in seen:
            name, n = "%s (%d)" % (base, n), n + 1
        seen.add(name)
        p["name"] = name
    names = [p["name"] for p in proxies]
    if len(names) > 1 and group_type == "select":
        group_type = "url-test"
    group = {"name": "VPN", "type": group_type, "proxies": names}
    if group_type in ("url-test", "fallback"):
        group.update(url="https://www.gstatic.com/generate_204",
                     interval=300)
    cfg = {
        "mode": "rule", "log-level": "info", "allow-lan": False,
        "ipv6": False, "unified-delay": True,
        "tun": tun_cfg,
        "proxies": proxies,
        "proxy-groups": [group],
        # Локальная сеть — мимо VPN: в режимах «устройства»/«все» в TUN
        # уходит весь трафик устройства, включая NAS и принтер.
        "rules": ["IP-CIDR,%s,DIRECT,no-resolve" % net for net in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                   "169.254.0.0/16")] + ["MATCH,VPN"],
    }
    if hijack_dns:
        cfg["dns"] = {
            "enable": True, "ipv6": False, "enhanced-mode": "redir-host",
            "nameserver": ["https://1.1.1.1/dns-query"],
            "proxy-server-nameserver": ["77.88.8.8", "1.1.1.1"],
            "respect-rules": True,
        }
    return cfg


def _save_engine_config(engine: str, name: str, cfg: dict) -> dict:
    from core.vpngen import generate as gen
    if engine == "singbox":
        text = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
        from core.singbox_manager import get_singbox_manager
        chk = get_singbox_manager().check_text(text)
        if not chk.get("ok") and not chk.get("no_binary"):
            raise WizardError("sing-box отверг конфиг: %s" % chk.get("error"))
    else:
        from core.clash_yaml import dump_yaml
        text = dump_yaml(cfg)
        from core.mihomo_manager import get_mihomo_manager
        try:
            chk = get_mihomo_manager().validate_via_binary(name, text=text)
        except Exception as e:                       # noqa: BLE001
            chk = {"ok": False, "error": str(e)}
        if (not chk.get("ok") and "не установлен" not in
                str(chk.get("error") or "")):
            raise WizardError("mihomo отверг конфиг: %s" % chk.get("error"))
    res = gen.save_output(engine, name, text)
    if not res.get("ok"):
        raise WizardError(res.get("error") or "конфиг не сохранён")
    return res


# ─────────────────────────────── apply ───────────────────────────────

def _destination(route: dict) -> dict:
    geosite, geoip = [], []
    wanted = set(route.get("services") or [])
    for svc in SERVICES:
        if svc["id"] in wanted:
            geosite += svc.get("geosite") or []
            geoip += svc.get("geoip") or []
    domains = []
    for d in route.get("domains") or []:
        d = str(d).strip().lower().rstrip(".")
        if d.startswith("http://") or d.startswith("https://"):
            d = d.split("://", 1)[1].split("/", 1)[0]
        if d and _DOMAIN_RE.match(d):
            domains.append(d)
        elif d:
            raise WizardError("«%s» — не похоже на адрес сайта" % d)
    list_ids = [str(x) for x in route.get("list_ids") or [] if x]
    known = _known_list_ids()
    unknown = [x for x in list_ids if known is not None and x not in known]
    if unknown:
        raise WizardError("списка «%s» нет — обновите страницу" % unknown[0])
    return {"geosite": sorted(set(geosite)), "geoip": sorted(set(geoip)),
            "domains": domains, "list_ids": list_ids, "cidrs": []}


def _known_list_ids():
    """id именованных списков или None, если список не прочитать."""
    try:
        from core import named_lists
        return {str(l.get("id")) for l in named_lists.list_all()
                if l.get("id")}
    except Exception:                                # noqa: BLE001
        return None


def _devices(route: dict, mode: str) -> list:
    if mode == "all":
        items = devices()
        if not items:
            raise WizardError("не найдено ни одного устройства в сети —"
                              " выберите устройства вручную или сайты")
        return [{"ip": d["ip"], "mac": d["mac"], "hostname": d["hostname"]}
                for d in items]
    out = []
    for item in route.get("devices") or []:
        ip = str(item.get("ip") if isinstance(item, dict) else item).strip()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise WizardError("«%s» — не IP-адрес устройства" % ip)
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            raise WizardError("«%s» — не адрес устройства в сети" % ip)
        # Адрес самого роутера: его ответы ушли бы в туннель, и
        # веб-интерфейс перестал бы открываться из домашней сети.
        if ip in _own_addresses():
            raise WizardError("«%s» — это адрес самого роутера" % ip)
        out.append({"ip": ip,
                    "hostname": (item.get("hostname") or "")
                    if isinstance(item, dict) else ""})
    if not out:
        raise WizardError("выберите хотя бы одно устройство")
    return out


def validate_plan(plan: dict) -> dict:
    plan = dict(plan or {})
    engine = str(plan.get("engine") or "")
    if engine not in ENGINES:
        raise WizardError("выберите программу")
    source = dict(plan.get("source") or {})
    kind = str(source.get("kind") or "")
    if kind not in ENGINES[engine]["sources"]:
        raise WizardError("для %s такой источник не подходит"
                          % ENGINES[engine]["label"])
    route = dict(plan.get("route") or {})
    mode = str(route.get("mode") or "sites")
    if mode not in ROUTE_MODES:
        raise WizardError("неизвестный режим маршрутизации")
    if mode == "sites":
        dest = _destination(route)
        if not any(dest.values()):
            raise WizardError("выберите хотя бы один сервис или сайт")
    devices_list = []
    if mode in ("devices", "all"):
        devices_list = _devices(route, mode)
    return {"engine": engine, "source": source, "kind": kind,
            "route": route, "mode": mode, "devices": devices_list,
            "transport": str(plan.get("transport") or "auto"),
            "autostart": bool(plan.get("autostart", True)),
            "name": str(plan.get("name") or "").strip()}


_apply_lock = threading.Lock()


def apply(plan: dict) -> dict:
    """Сохранить конфиг → поднять → автозапуск → маршрут. См. docstring.

    Один запуск за раз: двойное нажатие иначе зарегистрировало бы два
    устройства WARP и выбрало бы одно и то же имя TUN дважды.
    """
    if not _apply_lock.acquire(blocking=False):
        return {"ok": False, "steps": [],
                "error": "мастер уже выполняется — дождитесь результата"}
    try:
        return _apply(plan)
    finally:
        _apply_lock.release()


def _apply(plan: dict) -> dict:
    steps = []
    warnings = []
    try:
        p = validate_plan(plan)
    except WizardError as e:
        return {"ok": False, "error": str(e), "steps": steps}
    engine, kind, mode = p["engine"], p["kind"], p["mode"]

    def step(sid, ok, detail):
        steps.append({"step": sid, "ok": ok, "detail": detail})

    # 1) конфиг
    try:
        name, iface = _prepare_config(p, warnings)
    except WizardError as e:
        step("config", False, str(e))
        return {"ok": False, "error": str(e), "steps": steps}
    step("config", True, "конфиг «%s» готов" % name)

    # 2) запуск
    from core import tunnels_control
    running = _usque_running_iface(name) if engine == "usque" else ""
    try:
        res = ({"ok": True, "iface": running} if running
               else tunnels_control.up(engine, name))
    except Exception as e:                           # noqa: BLE001
        res = {"ok": False, "error": str(e)}
    if not res.get("ok"):
        msg = str(res.get("error") or res.get("message") or "не запустился")
        step("start", False, msg)
        return {"ok": False, "error": msg, "steps": steps, "name": name,
                "engine": engine}
    if engine == "usque":
        iface = res.get("iface") or iface
    elif engine == "awg":
        iface = name
    step("start", True, "запущен, интерфейс %s" % iface)

    # 3) автозапуск (не фатально)
    if p["autostart"]:
        ok, detail = _autostart(engine, name)
        step("autostart", ok, detail)
        if not ok:
            warnings.append("Автозапуск не включён: %s" % detail)

    # 4) маршрут
    method = "%s:%s" % (ENGINES[engine]["method"], iface)
    route_id = ""
    if mode != "none":
        route_doc = {"name": _route_name(p, name), "method": method,
                     "enabled": True}
        if mode == "sites":
            route_doc["destination"] = _destination(p["route"])
        else:
            route_doc["devices"] = p["devices"]
        from core.unified import manager
        r = manager.save_route(route_doc, apply=True, validate=True)
        applied = r.get("applied") or {}
        # save_route отвечает ok и тогда, когда маршрут сохранён, но в
        # ядре не применился (ipset/ip rule) — это тоже провал шага. Но
        # туннель и маршрут уже есть: «Попробовать ещё раз» с нуля дало
        # бы второе устройство WARP и дубль маршрута, поэтому отдаём
        # route_id и предлагаем диагностику, а не повтор.
        if r.get("ok") and applied.get("ok") is False:
            msg = "маршрут сохранён, но не применён: %s" % apply_error(applied)
            step("route", False, msg)
            return {"ok": False, "error": msg, "steps": steps,
                    "name": name, "engine": engine, "iface": iface,
                    "method": method, "partial": True,
                    "route_id": (r.get("route") or {}).get("id", ""),
                    "warnings": warnings}
        if not r.get("ok"):
            step("route", False, r.get("error") or "маршрут не создан")
            return {"ok": False, "error": r.get("error"), "steps": steps,
                    "name": name, "engine": engine, "iface": iface,
                    "method": method}
        route_id = (r.get("route") or {}).get("id", "")
        skipped = applied.get("skipped_selectors") or []
        warnings += [str(s) for s in skipped]
        step("route", True, "маршрут «%s» → %s" % (route_doc["name"], method))
    log.info("мастер: %s/%s запущен, маршрут %s" % (engine, name,
                                                     route_id or "—"),
             source="setup_wizard")
    return {"ok": True, "engine": engine, "name": name, "iface": iface,
            "method": method, "route_id": route_id, "steps": steps,
            "warnings": warnings}


def apply_error(applied: dict) -> str:
    """Текст ошибки применения маршрута: из него самого или из правил."""
    if applied.get("error"):
        return str(applied["error"])
    errs = [str(x.get("error")) for x in applied.get("applied") or []
            if isinstance(x, dict) and not x.get("ok")
            and not x.get("deferred") and x.get("error")]
    return "; ".join(errs) or "ошибка применения"


def _route_name(p: dict, name: str) -> str:
    mode = p["mode"]
    if mode == "sites":
        labels = [s["label"] for s in SERVICES
                  if s["id"] in set(p["route"].get("services") or [])]
        extra = len(p["route"].get("domains") or []) + len(
            p["route"].get("list_ids") or [])
        what = ", ".join(labels[:3]) + (" и ещё" if len(labels) > 3 or
                                        (labels and extra) else "")
        what = what or "Сайты"
    elif mode == "devices":
        what = "Устройства"
    else:
        what = "Все устройства"
    return ("%s → %s" % (what, name))[:60]


def _prepare_config(p: dict, warnings: list) -> tuple:
    """(имя конфига, iface или '') для выбранного источника."""
    from core.vpngen import generate as gen
    engine, kind, src = p["engine"], p["kind"], p["source"]
    transport = p["transport"]

    if engine in ("awg", "usque"):
        if kind == "existing":
            name = str(src.get("name") or "")
            if name not in _configs(engine):
                raise WizardError("конфига «%s» нет" % name)
            return name, ""
        if kind == "paste":
            text = str(src.get("text") or "")
            if not text.strip():
                raise WizardError("вставьте текст конфига")
            name = gen.unique_name(engine, p["name"] or (
                "vpn" if engine == "awg" else "warp-masque"))
            res = gen.save_output(engine, name, text)
            if not res.get("ok"):
                raise WizardError(res.get("error") or "конфиг не сохранён")
            return name, ""
        # generate
        req = dict(src.get("generate") or {})
        req.update(targets=[engine], save=True, transport=transport)
        if engine == "usque":
            req.update(provider="warp", protocol="masque")
        else:
            req.setdefault("protocol", "wireguard")
        if p["name"]:
            req["names"] = {engine: p["name"]}
        from core.vpngen.net import GenError
        try:
            res = gen.generate(req)
        except GenError as e:
            raise WizardError(str(e))
        item = (res.get("results") or {}).get(engine) or {}
        if not item.get("saved"):
            raise WizardError(item.get("error") or "конфиг не сохранён")
        warnings += [w for w in res.get("warnings") or []
                     if "одно и то же устройство" not in w]
        return item["name"], ""

    # sing-box / mihomo: новый конфиг с TUN из прокси источника.
    group_type = "select"
    if kind == "generate":
        proxies, profile = _generated_proxies(
            engine, dict(src.get("generate") or {}), transport)
        warnings += list(profile.get("warnings") or [])
        if profile.get("protocol") == "masque":
            group_type = "fallback"
        base = gen.base_name(profile)
    elif kind == "link":
        text = str(src.get("link") or "")
        if not text.strip():
            raise WizardError("вставьте ссылку или подписку")
        proxies = (_singbox_proxies_from_links(text, transport)
                   if engine == "singbox"
                   else _mihomo_proxies_from_links(text, transport))
        base = "proxy"
    else:
        cname = str(src.get("name") or "")
        if cname not in _configs(engine):
            raise WizardError("конфига «%s» нет" % cname)
        try:
            proxies = (_singbox_proxies_from_config(cname)
                       if engine == "singbox"
                       else _mihomo_proxies_from_config(cname))
        except (ValueError, json.JSONDecodeError) as e:
            raise WizardError("конфиг «%s» не читается: %s" % (cname, e))
        base = "%s-tun" % cname
    name = gen.unique_name(engine, p["name"] or base)
    taken = _taken_tun_names()
    if engine == "singbox":
        tun = pick_tun("sbtun", taken)
        cfg = singbox_tun_config(proxies, tun,
                                 hijack_dns=p["mode"] in ("devices", "all"),
                                 subnet_index=int(tun[5:] or 0))
    else:
        tun = pick_tun("mhtun", taken)
        cfg = mihomo_tun_config(proxies, tun,
                                hijack_dns=p["mode"] in ("devices", "all"),
                                group_type=group_type)
    _save_engine_config(engine, name, cfg)
    return name, tun


def _usque_running_iface(name: str) -> str:
    """Интерфейс уже запущенного профиля usque (или '')."""
    try:
        from core.usque_manager import get_usque_manager
        for c in get_usque_manager().list_configs():
            if c.get("name") == name and c.get("active"):
                return str(c.get("iface") or "")
    except Exception:                                # noqa: BLE001
        pass
    return ""


def _autostart(engine: str, name: str) -> tuple:
    try:
        if engine == "singbox":
            from core.singbox_autostart import set_autostart, regenerate
            r = set_autostart(name, True)
            if r.get("ok"):
                r = regenerate() or {"ok": True}
        elif engine == "mihomo":
            from core.mihomo_autostart import set_autostart, regenerate
            r = set_autostart(name, True)
            if r.get("ok"):
                r = regenerate() or {"ok": True}
        elif engine == "awg":
            from core.awg_autostart_manager import get_awg_autostart_manager
            r = get_awg_autostart_manager().set_enabled(name, True)
        else:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            # usque поднимает при старте GUI все свои профили, если
            # включены оба флага (app.py::_apply_usque_autostart_on_boot).
            cfg.set("usque", "enabled", True)
            cfg.set("usque", "autostart", True)
            cfg.save()
            r = {"ok": True}
    except Exception as e:                           # noqa: BLE001
        return False, str(e)
    if not isinstance(r, dict):
        r = {"ok": bool(r)}
    if not r.get("ok"):
        return False, str(r.get("error") or r.get("message") or "ошибка")
    return True, "включён"
