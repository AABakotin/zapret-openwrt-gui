# core/vpngen/generate.py
"""
Генератор конфигов: одна регистрация → конфиги под нужные движки.

Поток одного вызова ``generate(request)``:

1. ``normalize_options`` проверяет и доводит опции (DNS, MTU, маски…);
2. профиль берётся у провайдера (``warp`` / ``proton``) через транспорт
   (напрямую, через обход или «авто» — ``core.vpngen.net``);
3. ``render`` превращает профиль в текст конфига каждого выбранного
   движка;
4. при ``save`` конфиги сохраняются их же менеджерами — с проверкой
   формата и **без перезаписи**: имя занято → берётся ``имя-2``.

Совместимость «провайдер × протокол × движок» — в ``TARGETS``: MASQUE
понимают usque и mihomo, WireGuard — AmneziaWG, sing-box и mihomo.

Один и тот же профиль в нескольких движках — это одно устройство WARP
(один адрес в туннеле). Поднимать такие конфиги одновременно нельзя —
это сказано и в предупреждениях результата.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import threading

from core.log_buffer import log
from core.vpngen import presets, render
from core.vpngen.net import GenError, run_with_transport

TARGETS = {
    "awg": {"label": "AmneziaWG", "protocols": ("wireguard",),
            "format": "conf"},
    "usque": {"label": "WARP/MASQUE (usque)", "protocols": ("masque",),
              "format": "json"},
    "singbox": {"label": "sing-box", "protocols": ("wireguard",),
                "format": "json"},
    "mihomo": {"label": "mihomo", "protocols": ("wireguard", "masque"),
               "format": "yaml"},
}

PROVIDERS = {
    "warp": {"label": "Cloudflare WARP",
             "protocols": ("wireguard", "masque"),
             "sources": ("native", "service")},
    "proton": {"label": "Proton VPN (бесплатные серверы)",
               "protocols": ("wireguard",),
               "sources": ("service", "import")},
}

_NAME_RE = {
    "awg": re.compile(r"^[A-Za-z0-9_.\-]{1,15}$"),
    "usque": re.compile(r"^[A-Za-z0-9_\-]{1,64}$"),
    "singbox": re.compile(r"^[A-Za-z0-9_.\-]{1,32}$"),
    "mihomo": re.compile(r"^[A-Za-z0-9_.\-]{1,32}$"),
}
_MAX_NAME = {"awg": 15, "usque": 64, "singbox": 32, "mihomo": 32}

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")

AWG3_FIELDS = ("ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
               "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts")
_RANGE_RE = re.compile(r"^\d{1,9}(?:-\d{1,9})?$")


def compatible_targets(provider: str, protocol: str) -> list:
    return [t for t, spec in TARGETS.items()
            if protocol in spec["protocols"]
            and not (t == "usque" and provider != "warp")]


# ─────────────────────────────── опции ───────────────────────────────

def _int(value, default: int, lo: int, hi: int, what: str) -> int:
    if value in (None, ""):
        return default
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise GenError("%s: нужно число" % what)
    if not lo <= v <= hi:
        raise GenError("%s: допустимо %d..%d" % (what, lo, hi))
    return v


def _host_ok(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(_HOST_RE.match(host))


def _parse_endpoint(text: str) -> tuple:
    s = str(text or "").strip()
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, _, port = s.rpartition(":")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise GenError("endpoint: нужен вид адрес:порт, например"
                       " 162.159.192.1:2408")
    if not _host_ok(host):
        raise GenError("endpoint: «%s» — не адрес и не имя" % host)
    return host, int(port)


def _list(value) -> list:
    if isinstance(value, str):
        value = re.split(r"[\s,;]+", value)
    return [str(v).strip() for v in (value or []) if str(v).strip()]


def default_sni() -> str:
    try:
        from core.config_manager import get_config_manager
        return str(get_config_manager().get("usque", "default_sni",
                                            default="") or "")
    except Exception:
        return ""


def normalize_options(provider: str, protocol: str, raw: dict) -> dict:
    """Опции запроса → проверенный словарь для рендеров."""
    raw = dict(raw or {})
    ipv6 = bool(raw.get("ipv6", True))
    opts = {
        "ipv6": ipv6,
        "mtu": _int(raw.get("mtu"), 1280 if provider == "warp" else 1420,
                    1200, 1500, "MTU"),
        "keepalive": _int(raw.get("keepalive"), 25, 0, 600, "keepalive"),
        "dns": presets.dns_servers(
            str(raw.get("dns") or ("provider" if provider == "proton"
                                   else "cloudflare")),
            ipv6=ipv6, provider=provider, custom=_list(raw.get("dns_custom"))),
        "allowed": presets.allowed_ips(
            str(raw.get("allowed") or "all"), ipv6=ipv6,
            custom=_list(raw.get("allowed_custom"))),
        "label": str(raw.get("label") or "").strip()[:40],
    }
    if protocol == "masque":
        opts["mtu"] = 1280                 # MASQUE поддерживает только 1280
        sni = str(raw.get("sni") if raw.get("sni") is not None
                  else default_sni()).strip()
        if sni and not _HOST_RE.match(sni):
            raise GenError("SNI: нужно доменное имя (например ozon.ru)")
        opts["sni"] = sni
        return opts

    # Endpoint: только WARP; у Proton адрес задаёт выбранный сервер.
    mode = str(raw.get("endpoint_mode") or "account")
    if provider == "warp" and mode == "random":
        opts["endpoint_host"], opts["endpoint_port"] = \
            presets.random_warp_endpoint()
    elif mode == "custom" and raw.get("endpoint"):
        opts["endpoint_host"], opts["endpoint_port"] = \
            _parse_endpoint(raw["endpoint"])

    junk = raw.get("junk")
    if isinstance(junk, dict):
        jc = _int(junk.get("Jc"), 0, 0, 128, "Jc")
        jmin = _int(junk.get("Jmin"), 0, 0, 1280, "Jmin")
        jmax = _int(junk.get("Jmax"), 0, 0, 1280, "Jmax")
        if jc and jmin > jmax:
            raise GenError("Jmin не может быть больше Jmax")
        opts["junk"] = {"Jc": jc, "Jmin": jmin, "Jmax": jmax}
    else:
        opts["junk"] = presets.junk(str(junk or "light"))
    try:
        opts["masks"] = presets.masks(
            str(raw.get("mask") or "none"), sni=str(raw.get("mask_sni") or ""),
            custom=str(raw.get("mask_custom") or ""),
            full_quic=bool(raw.get("mask_full", True)))
    except ValueError as e:
        raise GenError(str(e))
    if opts["masks"].get("I1", "").startswith("<b 0x") and \
            len(opts["masks"]["I1"]) > 2 * 1400:
        raise GenError("I1 длиннее 1400 байт — система нарежет его на"
                       " фрагменты, что заметнее самого WireGuard")
    awg3 = {}
    for key in AWG3_FIELDS:
        value = str((raw.get("awg3") or {}).get(key) or "").strip()
        if value:
            if not _RANGE_RE.match(value):
                raise GenError("%s: число или диапазон «a-b»" % key)
            awg3[key] = value
    opts["awg3"] = awg3
    return opts


# ─────────────────────────────── имена ───────────────────────────────

def _existing_names(target: str, strict: bool = False) -> set:
    """Имена конфигов движка. ``strict`` — ошибка чтения не глотается:
    перед сохранением «пустой список» значил бы перезапись чужого."""
    try:
        if target == "awg":
            from core.awg_manager import get_awg_manager
            return {c.get("name") for c in get_awg_manager().list_configs()}
        if target == "usque":
            from core.usque_manager import get_usque_manager
            return {c.get("name") for c in get_usque_manager().list_configs()}
        if target == "singbox":
            from core.singbox_manager import get_singbox_manager
            return {c.get("name")
                    for c in get_singbox_manager().list_configs()}
        if target == "mihomo":
            from core.mihomo_manager import get_mihomo_manager
            return {c.get("name") for c in get_mihomo_manager().list_configs()}
    except Exception as e:                           # noqa: BLE001
        if strict:
            raise GenError("список конфигов %s не получен: %s" % (target, e))
        log.warning("vpngen: список конфигов %s не получен: %s"
                    % (target, e), source="vpngen")
    return set()


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]+", "-", text).strip("-.").lower()


def base_name(profile: dict) -> str:
    if profile.get("provider") == "proton":
        country = (profile.get("server") or {}).get("country") or ""
        return _slug("proton-%s" % country) if country else "proton"
    return "warp-masque" if profile.get("protocol") == "masque" else "warp"


def unique_name(target: str, wanted: str, taken=None) -> str:
    """Свободное имя для движка: ``wanted``, ``wanted-2``, …"""
    taken = set(taken if taken is not None else _existing_names(target))
    limit = _MAX_NAME[target]
    base = _slug(wanted or "vpn")[:limit] or "vpn"
    if base not in taken and _NAME_RE[target].match(base):
        return base
    for n in range(2, 1000):
        suffix = "-%d" % n
        name = base[:limit - len(suffix)] + suffix
        if name not in taken:
            return name
    raise GenError("не удалось подобрать имя для %s" % target)


def valid_name(target: str, name: str) -> bool:
    return bool(_NAME_RE[target].match(name or ""))


# ─────────────────────────── локальные порты ─────────────────────────

_PORT_RES = (re.compile(r'"listen_port"\s*:\s*(\d+)'),
             re.compile(r"^\s*(?:mixed-port|port|socks-port|redir-port|"
                        r"tproxy-port)\s*:\s*(\d+)", re.M),
             re.compile(r"external-controller\s*:\s*['\"]?[^:\s]*:(\d+)"))


def _ports_in_configs() -> set:
    used = set()
    for target in ("singbox", "mihomo"):
        for name in _existing_names(target):
            try:
                from core import tunnels_control
                text = tunnels_control.config_get(target, name).get("text")
            except Exception:                        # noqa: BLE001
                continue
            for rx in _PORT_RES:
                used.update(int(m) for m in rx.findall(text or ""))
    return used


def _port_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def pick_listen_port(start: int, taken=None) -> int:
    """Локальный порт, который не занят ни сейчас, ни другим конфигом."""
    taken = set(taken or ()) | _ports_in_configs()
    for port in range(start, start + 200):
        if port not in taken and _port_free(port):
            return port
    return start


# ───────────────────────────── сохранение ────────────────────────────

_save_lock = threading.Lock()


def save_output(target: str, name: str, text: str) -> dict:
    """Сохранить текст конфига движком ``target`` (без перезаписи).

    Проверка «имя занято» и запись — под одним замком: менеджеры sing-box
    и mihomo пишут через os.replace и сами чужой файл не берегут.
    """
    with _save_lock:
        try:
            return _save_output(target, name, text)
        except GenError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:                       # noqa: BLE001
            # OSError (флеш только для чтения, нет места) и прочее — ответом,
            # а не исключением: иначе генерация бросила бы уже сохранённое.
            log.error("vpngen: %s «%s» не сохранён: %s" % (target, name, e),
                      source="vpngen")
            return {"ok": False, "error": "не сохранено: %s" % e}


def _save_output(target: str, name: str, text: str) -> dict:
    if target not in TARGETS:
        return {"ok": False, "error": "неизвестный движок %s" % target}
    if not valid_name(target, name):
        return {"ok": False,
                "error": "имя «%s» не подходит для %s (латиница, цифры,"
                         " «-_.», до %d символов)"
                         % (name, TARGETS[target]["label"],
                            _MAX_NAME[target])}
    if name in _existing_names(target, strict=True):
        return {"ok": False, "error": "конфиг «%s» уже есть" % name}
    try:
        if target == "awg":
            from core.awg_manager import get_awg_manager
            get_awg_manager().save_config(name, text=text,
                                          allow_overwrite=False)
            res = {"ok": True}
        elif target == "usque":
            from core.usque_manager import get_usque_manager
            res = get_usque_manager().import_config(name, text)
        elif target == "singbox":
            from core.singbox_manager import get_singbox_manager
            res = get_singbox_manager().save_config(name, text=text)
        else:
            from core.mihomo_manager import get_mihomo_manager
            res = get_mihomo_manager().save_config(name, text)
    except FileExistsError:
        return {"ok": False, "error": "конфиг «%s» уже есть" % name}
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not isinstance(res, dict):
        res = {"ok": bool(res)}
    out = {"ok": bool(res.get("ok")), "name": name}
    if not out["ok"]:
        out["error"] = res.get("error") or "не сохранено"
    if res.get("warnings"):
        out["warnings"] = res["warnings"]
    if out["ok"]:
        log.info("vpngen: сохранён %s/%s" % (target, name), source="vpngen")
    return out


# ───────────────────────── проверка синтаксиса ───────────────────────

CHECK_TARGETS = tuple(TARGETS) + ("proton-import",)


def check_output(target: str, text: str) -> dict:
    """Проверить текст конфига, ничего не сохраняя.

    Сначала встроенный разбор (есть всегда), затем — если движок
    установлен — сам бинарь (`sing-box check`, `mihomo -t`): он строже и
    знает свою версию. Ответ: ``{ok, errors, checked_by, warnings}``.
    """
    text = str(text or "")
    if target not in CHECK_TARGETS:
        return {"ok": False, "errors": ["неизвестный движок %s" % target],
                "checked_by": []}
    if not text.strip():
        return {"ok": False, "errors": ["конфиг пустой"], "checked_by": []}
    checker = {"awg": _check_awg, "usque": _check_usque,
               "singbox": _check_singbox, "mihomo": _check_mihomo,
               "proton-import": _check_proton}[target]
    try:
        res = checker(text)
    except Exception as e:                           # noqa: BLE001
        log.error("vpngen: проверка %s упала: %s" % (target, e),
                  source="vpngen")
        res = {"errors": ["проверка не выполнена: %s" % e], "checked_by": []}
    res.setdefault("warnings", [])
    res["ok"] = not res.get("errors")
    return res


def _check_awg(text: str) -> dict:
    from core.awg_config import parse_conf, validate
    try:
        cfg = parse_conf(text)
    except Exception as e:                           # noqa: BLE001
        return {"errors": ["не разбирается: %s" % e],
                "checked_by": ["разбор AmneziaWG"]}
    return {"errors": list(validate(cfg)),
            "checked_by": ["разбор AmneziaWG"]}


def _check_usque(text: str) -> dict:
    import base64
    import json
    from core.usque_manager import UsqueManager
    by = ["разбор usque config.json"]
    try:
        data = json.loads(text)
    except ValueError as e:
        return {"errors": ["не JSON: %s" % e], "checked_by": by}
    if not isinstance(data, dict):
        return {"errors": ["ожидается JSON-объект"], "checked_by": by}
    errors = ["нет поля %s" % k for k in UsqueManager._USQUE_REQUIRED
              if not data.get(k)]
    if data.get("private_key"):
        try:
            base64.b64decode(str(data["private_key"]), validate=True)
        except ValueError:
            errors.append("private_key — не base64 (нужен DER-ключ P-256)")
    for key in ("endpoint_v4", "endpoint_v6", "ipv4", "ipv6"):
        value = str(data.get(key) or "")
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                errors.append("%s — не IP-адрес: %s" % (key, value))
    if not data.get("endpoint_v4") and not data.get("endpoint_v6"):
        errors.append("нет адреса сервера (endpoint_v4/endpoint_v6)")
    if "BEGIN PUBLIC KEY" not in str(data.get("endpoint_pub_key") or ""):
        errors.append("endpoint_pub_key — нужен PEM публичного ключа")
    return {"errors": errors, "checked_by": by}


def _check_singbox(text: str) -> dict:
    from core.singbox_config import parse_conf, validate
    by = ["разбор sing-box"]
    try:
        cfg = parse_conf(text)
    except ValueError as e:
        return {"errors": ["не разбирается: %s" % e], "checked_by": by}
    errors = list(validate(cfg))
    if errors:
        return {"errors": errors, "checked_by": by}
    from core.singbox_manager import get_singbox_manager
    chk = get_singbox_manager().check_text(text)
    if chk.get("no_binary"):
        return {"errors": [], "checked_by": by,
                "warnings": ["sing-box не установлен — проверен только"
                             " синтаксис, без самого движка"]}
    by.append("sing-box check")
    return {"errors": [] if chk.get("ok") else
            [chk.get("error") or "sing-box отверг конфиг"], "checked_by": by}


_EXTERNAL_DATA = re.compile(
    r"\b(?:GEOIP|GEOSITE|RULE-SET|SRC-GEOIP|GEOIP6)\s*,|"
    r"^\s*(?:rule-providers|proxy-providers|geox-url|geodata-mode)\s*:",
    re.M | re.I)


def _check_mihomo(text: str) -> dict:
    from core.clash_yaml import parse_yaml
    by = ["разбор YAML"]
    try:
        cfg = parse_yaml(text)
    except Exception as e:                           # noqa: BLE001
        return {"errors": ["не разбирается: %s" % e], "checked_by": by}
    if not isinstance(cfg, dict) or not cfg:
        return {"errors": ["ожидается YAML-словарь"], "checked_by": by}
    if not cfg.get("proxies") and not cfg.get("proxy-providers"):
        return {"errors": ["нет ни одного прокси (proxies)"],
                "checked_by": by}
    from core.mihomo_manager import get_mihomo_manager
    mgr = get_mihomo_manager()
    if not mgr._binary():
        return {"errors": [], "checked_by": by,
                "warnings": ["mihomo не установлен — проверен только"
                             " синтаксис, без самого движка"]}
    if _EXTERNAL_DATA.search(text):
        # geo-базы и провайдеры mihomo -t может пойти скачивать — а
        # проверка обещает «без сети». Такой конфиг не запускаем.
        return {"errors": [], "checked_by": by,
                "warnings": ["конфиг ссылается на внешние базы (GEOIP/"
                             "GEOSITE/провайдеры) — mihomo -t не запускали,"
                             " проверен только синтаксис"]}
    chk = mgr.validate_via_binary("", text=text)
    by.append("mihomo -t")
    return {"errors": [] if chk.get("ok") else
            [chk.get("reason") or chk.get("error") or "mihomo отверг конфиг"],
            "checked_by": by}


def _check_proton(text: str) -> dict:
    from core.vpngen import proton
    try:
        prof = proton.from_config(text)
    except GenError as e:
        return {"errors": [str(e)], "checked_by": ["разбор конфига Proton"]}
    srv = prof.get("server") or {}
    return {"errors": [], "checked_by": ["разбор конфига Proton"],
            "summary": "сервер %s, %s:%d" % (
                srv.get("name") or "без имени", prof["endpoint_host"],
                prof["endpoint_port"])}


def delete_output(target: str, name: str) -> dict:
    """Удалить созданный генератором конфиг (откат MCP)."""
    try:
        if target == "awg":
            from core.awg_manager import get_awg_manager
            mgr = get_awg_manager()
            if mgr.is_running(name):
                return {"ok": False, "error": "%s запущен" % name}
            return mgr.delete_config(name) or {"ok": True}
        if target == "usque":
            import os
            from core.usque_manager import get_usque_manager
            mgr = get_usque_manager()
            for c in mgr.list_configs():
                if c.get("name") == name:
                    if c.get("active"):
                        return {"ok": False, "error": "%s запущен" % name}
                    os.remove(c["path"])
                    mgr.forget_iface(c["path"])
                    return {"ok": True}
            return {"ok": False, "error": "конфига %s нет" % name}
        if target == "singbox":
            from core.singbox_manager import get_singbox_manager
            return get_singbox_manager().delete_config(name)
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().delete_config(name)
    except Exception as e:                           # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ────────────────────────────── генерация ────────────────────────────

def _profile(provider: str, protocol: str, source: str, transport: str,
             req: dict) -> dict:
    if provider == "proton":
        from core.vpngen import proton
        if source == "import":
            # Готовый конфиг Proton: сеть не нужна, порт — из конфига,
            # если пользователь не выбрал другой явно.
            return proton.from_config(
                str(req.get("config") or ""),
                port=_int(req.get("port"), 0, 0, 65535, "порт Proton")
                if req.get("port") else 0)
        return proton.generate(transport,
                               server_id=str(req.get("server_id") or ""),
                               country=str(req.get("country") or ""),
                               port=_int(req.get("port"), 51820, 1, 65535,
                                         "порт Proton"))
    from core.vpngen import warp
    return warp.generate(protocol, source, transport,
                         license_key=str(req.get("license") or ""),
                         device_name=str(req.get("device_name") or "")[:64],
                         jwt=str(req.get("team_token") or ""))


def render_target(target: str, profile: dict, opts: dict) -> str:
    if target == "awg":
        return render.awg_conf(profile, opts)
    if target == "usque":
        return render.usque_json(profile, opts)
    if target == "singbox":
        return render.singbox_json(profile, opts)
    return render.mihomo_yaml(profile, opts)


def _label(profile: dict, opts: dict) -> str:
    if opts.get("label"):
        return opts["label"]
    if profile.get("provider") == "proton":
        srv = profile.get("server") or {}
        return ("Proton %s" % (srv.get("name") or srv.get("country") or "")
                ).strip()
    return "WARP MASQUE" if profile.get("protocol") == "masque" else "WARP"


def generate(req: dict) -> dict:
    """Сгенерировать конфиги. См. docstring модуля и ``api/vpngen.py``."""
    req = dict(req or {})
    provider = str(req.get("provider") or "warp")
    if provider not in PROVIDERS:
        raise GenError("неизвестный провайдер «%s»" % provider)
    spec = PROVIDERS[provider]
    protocol = str(req.get("protocol") or spec["protocols"][0])
    if protocol not in spec["protocols"]:
        raise GenError("%s не умеет %s" % (spec["label"], protocol))
    source = str(req.get("source") or spec["sources"][0])
    if source not in spec["sources"]:
        raise GenError("источник «%s» недоступен для %s"
                       % (source, spec["label"]))
    allowed = compatible_targets(provider, protocol)
    targets = [t for t in (req.get("targets") or allowed) if t]
    bad = [t for t in targets if t not in allowed]
    if bad:
        raise GenError("%s не поддерживает %s; подходят: %s" % (
            ", ".join(TARGETS[t]["label"] if t in TARGETS else t
                      for t in bad),
            protocol, ", ".join(TARGETS[t]["label"] for t in allowed)))
    if not targets:
        raise GenError("не выбрано ни одного движка")

    opts = normalize_options(provider, protocol, req.get("options") or {})
    transport = str(req.get("transport") or "auto")

    profile, used, tried = run_with_transport(
        transport,
        lambda t: _profile(provider, protocol, source, t, req))
    opts["label"] = _label(profile, opts)

    names = req.get("names") or {}
    base = base_name(profile)
    save = bool(req.get("save"))
    results = {}
    taken_ports = set()
    for target in targets:
        topts = dict(opts)
        if target in ("singbox", "mihomo"):
            port = pick_listen_port(1080 if target == "singbox" else 7890,
                                    taken_ports)
            taken_ports.add(port)
            topts["listen_port"] = port
        text = render_target(target, profile, topts)
        wanted = str(names.get(target) or "").strip()
        name = wanted if wanted else unique_name(target, base)
        item = {"target": target, "label": TARGETS[target]["label"],
                "format": TARGETS[target]["format"], "name": name,
                "text": text, "saved": False}
        if "listen_port" in topts:
            item["listen_port"] = topts["listen_port"]
        if save:
            res = save_output(target, name, text)
            item["saved"] = res["ok"]
            if not res["ok"]:
                item["error"] = res.get("error")
            if res.get("warnings"):
                item["warnings"] = res["warnings"]
        results[target] = item

    warnings = list(profile.get("warnings") or [])
    if len(targets) > 1:
        warnings.append("Все конфиги — одно и то же устройство %s: держите"
                        " запущенным только один из них, иначе туннели"
                        " будут мешать друг другу."
                        % PROVIDERS[provider]["label"])
    if protocol == "wireguard" and "singbox" in targets and (
            opts.get("masks") or (opts.get("junk") or {}).get("Jc")):
        warnings.append("sing-box не умеет обфускацию AmneziaWG: в его"
                        " конфиге обычный WireGuard (Jc/I1 — только в AWG"
                        " и mihomo).")
    return {
        "ok": all(r.get("saved") for r in results.values()) if save else True,
        "provider": provider, "protocol": protocol, "source": source,
        "transport": used, "tried": tried,
        "account": profile.get("account") or {},
        "server": profile.get("server"),
        "results": results,
        "warnings": warnings,
        "secrets": _secret_values(profile),
    }


def _secret_values(profile: dict) -> list:
    """Значения, которые нельзя показывать модели (для маскировки MCP)."""
    return [v for v in (profile.get("private_key"),
                        profile.get("access_token"))
            if v and v not in ("service",)]


def mask(text: str, secrets_list) -> str:
    for value in secrets_list or ():
        text = text.replace(value, "«скрыто»")
    return text


def options() -> dict:
    """Всё, что нужно форме генератора и MCP."""
    from core.vpngen.net import transports_for
    installed = _installed()
    return {
        "ok": True,
        "providers": [dict(id=k, label=v["label"],
                           protocols=list(v["protocols"]),
                           sources=list(v["sources"]))
                      for k, v in PROVIDERS.items()],
        "targets": [dict(id=k, label=v["label"],
                         protocols=list(v["protocols"]),
                         installed=installed.get(k, False))
                    for k, v in TARGETS.items()],
        "dns": [{"id": p["id"], "label": p["label"]}
                for p in presets.DNS_PRESETS] + [{"id": "custom",
                                                  "label": "Свои адреса"}],
        "allowed": presets.ALLOWED_PRESETS,
        "endpoint_modes": presets.ENDPOINT_MODES,
        "junk": presets.JUNK_PRESETS,
        "masks": presets.MASK_PROFILES,
        "awg3_fields": list(AWG3_FIELDS),
        "proton_ports": list(presets.PROTON_PORTS),
        "sni_domains": list(presets.QUIC_SNI_DOMAINS),
        "default_sni": default_sni(),
        "transports": _transport_list(),
        "auto_order": transports_for("auto"),
    }


def _transport_list() -> list:
    out = [{"id": "auto", "label": "Авто (напрямую, при блокировке — через"
                                   " обход)"}]
    try:
        from core.download_transport import list_transports
        for t in list_transports().get("transports") or []:
            out.append({"id": t.get("id"), "label": t.get("label")
                        or t.get("id")})
    except Exception:                                # noqa: BLE001
        out.append({"id": "direct", "label": "Напрямую"})
    return out


def _installed() -> dict:
    out = {}
    try:
        from core.awg_installer import get_awg_installer
        out["awg"] = bool(get_awg_installer().get_installed_version()
                          .get("installed"))
    except Exception:                                # noqa: BLE001
        pass
    try:
        from core.usque_manager import get_usque_manager
        out["usque"] = bool(get_usque_manager().detect().get("installed"))
    except Exception:                                # noqa: BLE001
        pass
    for target, mod in (("singbox", "core.singbox_detector"),
                        ("mihomo", "core.mihomo_detector")):
        try:
            module = __import__(mod, fromlist=["x"])
            getter = getattr(module, "get_%s_detector" % target)
            out[target] = bool(getter().detect_binary().get("installed"))
        except Exception:                            # noqa: BLE001
            pass
    return out
