# core/vpngen/proton.py
"""
Proton VPN (бесплатные серверы) через сервис-генератор.

Своего анонимного API у Proton нет: доступ к WireGuard выдаётся под
учётную запись. Сервис proton-generation (``api-proton.workers.dev``)
держит сессию у себя и по ней отдаёт список бесплатных серверов и
подписывает сертификат на наш ключ. Мы повторяем то же, что делает его
страница, но ключ создаём НА РОУТЕРЕ:

1. ``/api/proton/session`` → сессия (живёт около суток);
2. ``/api/proton/servers`` → серверы: страна, город, нагрузка, entry-IP
   и публичный ключ WireGuard;
3. ``/api/proton/certificate`` с нашим **публичным** Ed25519 — Proton
   разрешает вход по WireGuard-ключу, выведенному из того же скаляра
   (``core.vpngen.keys.proton_keypair``). Приватный ключ сервису не
   отправляется никогда.

Адреса в туннеле у бесплатного Proton фиксированные: 10.2.0.2/32 и
2a07:b944::2:2/128, DNS — 10.2.0.1.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import threading
import time

from core.log_buffer import log
from core.vpngen import keys
from core.vpngen.net import GenError, request_json

DEFAULT_SERVICE = "https://www.api-proton.workers.dev"
SESSION_TTL = 23 * 3600

ADDRESS_V4 = "10.2.0.2"
ADDRESS_V6 = "2a07:b944::2:2"

_lock = threading.Lock()
_state = {"session": None, "expires": 0.0, "servers": [], "service": ""}


def service_url() -> str:
    try:
        from core.config_manager import get_config_manager
        url = get_config_manager().get("vpngen", "proton_service",
                                       default=DEFAULT_SERVICE)
    except Exception:
        url = DEFAULT_SERVICE
    url = str(url or DEFAULT_SERVICE).strip().rstrip("/")
    return url if url.startswith("https://") else DEFAULT_SERVICE


def _call(path: str, body: dict, transport: str) -> dict:
    data = request_json("POST", service_url() + path, body=body,
                        transport=transport, retries=1)
    if not isinstance(data, dict):
        raise GenError("сервис Proton вернул не объект")
    # Как у клиента proton-generation: успех — только явный ok. Ответ без
    # ok (например, {"error": …}) — отказ, иначе получился бы конфиг для
    # ключа, который Proton не авторизовал.
    if data.get("ok") is not True:
        msg = str(data.get("error") or "неизвестная ошибка")
        low = msg.lower()
        if "token" in low or "session" in low:
            reset()
            raise GenError("сессия Proton устарела — запросите серверы"
                           " заново")
        raise GenError("сервис Proton: %s" % msg)
    return data


def reset() -> None:
    with _lock:
        _state.update(session=None, expires=0.0, servers=[])


def _load(value) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def _normalize(srv: dict) -> dict:
    return {
        "id": str(srv.get("id") or ""),
        "name": str(srv.get("name") or "").replace("-FREE#", " #"),
        "country": str(srv.get("exitCountry") or srv.get("country") or ""),
        "city": str(srv.get("city") or ""),
        "load": _load(srv.get("load")),
        "entry_ip": str(srv.get("entryIp") or srv.get("entry_ip") or ""),
        "public_key": str(srv.get("publicKey") or srv.get("public_key")
                          or ""),
    }


def servers(transport: str, *, refresh: bool = False) -> dict:
    """Список бесплатных серверов (с кешем сессии)."""
    with _lock:
        cached = (_state["session"] and time.time() < _state["expires"]
                  and _state["servers"] and _state["service"] == service_url())
        if cached and not refresh:
            return {"servers": list(_state["servers"]), "cached": True}
    if refresh or not cached:
        sess = _call("/api/proton/session", {}, transport).get("session")
        if not sess:
            raise GenError("сервис Proton не выдал сессию")
        with _lock:
            _state.update(session=sess, expires=time.time() + SESSION_TTL,
                          service=service_url())
    with _lock:
        sess = _state["session"]
    data = _call("/api/proton/servers", {"session": sess}, transport)
    items = [_normalize(s) for s in data.get("servers") or []
             if isinstance(s, dict)]
    items = [s for s in items if s["entry_ip"] and s["public_key"]]
    items.sort(key=lambda s: (s["country"], s["load"], s["name"]))
    with _lock:
        _state["servers"] = items
    log.info("vpngen: Proton — %d серверов" % len(items), source="vpngen")
    return {"servers": items, "cached": False}


def generate(transport: str, *, server_id: str = "", country: str = "",
             port: int = 51820) -> dict:
    """Профиль WireGuard для сервера Proton.

    Без ``server_id`` берётся наименее нагруженный сервер страны
    ``country`` (или вообще любой).
    """
    listing = servers(transport)["servers"]
    if not listing:
        raise GenError("сервис Proton не вернул ни одного сервера")
    chosen = None
    if server_id:
        chosen = next((s for s in listing if s["id"] == server_id), None)
        if chosen is None:
            raise GenError("сервер Proton «%s» не найден — обновите список"
                           % server_id)
    else:
        pool = [s for s in listing
                if not country or s["country"].upper() == country.upper()]
        if not pool:
            raise GenError("нет бесплатных серверов Proton в стране %s"
                           % country)
        chosen = min(pool, key=lambda s: s["load"])

    pair = keys.proton_keypair()
    with _lock:
        sess = _state["session"]
    _call("/api/proton/certificate", {"session": sess,
                                      "clientPublicKey": pair["ed25519_pem"],
                                      "persistent": True}, transport)
    return {
        "provider": "proton", "protocol": "wireguard", "source": "service",
        "service": service_url(),
        "private_key": pair["wg_private"],
        "peer_public_key": chosen["public_key"],
        "ipv4": ADDRESS_V4, "ipv6": ADDRESS_V6,
        "endpoint_host": chosen["entry_ip"],
        "endpoint_port": int(port or 51820),
        "reserved": [],
        "server": chosen,
        "account": {"id": "", "type": "proton-free"},
        "warnings": ["Proton: сертификат выдан через сервис %s. Ключ"
                     " WireGuard создан на роутере и сервису не"
                     " передавался." % service_url()],
    }


# ───────────────────────── импорт готового конфига ─────────────────────

_SERVER_COMMENT = re.compile(r"^\s*#\s*([A-Z]{2}(?:[-#A-Z0-9 ]*))\s*$", re.M)


def from_config(text: str, *, port: int = 0) -> dict:
    """Профиль из WireGuard-конфига Proton (аккаунт или proton-generation).

    Запасной путь, когда сервис-генератор недоступен: пользователь скачал
    конфиг сам — в аккаунте Proton (Загрузки → WireGuard, бесплатный
    тариф тоже) или на странице proton-generation в браузере. Ключ уже
    авторизован Proton, мы лишь пересобираем конфиг под нужные движки
    (маскировка AmneziaWG, sing-box, mihomo).
    """
    from core.awg_config import parse_conf
    text = str(text or "").strip()
    if not text:
        raise GenError("вставьте WireGuard-конфиг Proton")
    try:
        cfg = parse_conf(text)
    except Exception as e:                           # noqa: BLE001
        raise GenError("конфиг не читается: %s" % e)
    iface = cfg.get("interface") or {}
    peers = cfg.get("peers") or []
    if not peers:
        raise GenError("в конфиге нет секции [Peer]")
    if len(peers) > 1:
        raise GenError("в конфиге %d секций [Peer] — нужен конфиг одного"
                       " сервера Proton" % len(peers))
    peer = peers[0]
    if str(peer.get("PresharedKey") or "").strip():
        # Рендеры PresharedKey не переносят — туннель не поднялся бы.
        raise GenError("конфиг с PresharedKey не поддерживается — скачайте"
                       " в аккаунте Proton обычный WireGuard-конфиг")
    priv = str(iface.get("PrivateKey") or "").strip()
    pub = str(peer.get("PublicKey") or "").strip()
    for label, value in (("PrivateKey", priv), ("PublicKey", pub)):
        if not _is_wg_key(value):
            raise GenError("%s в конфиге не похож на ключ WireGuard" % label)
    host, cport = _split_endpoint(str(peer.get("Endpoint") or ""))
    v4 = v6 = ""
    addrs = iface.get("Address") or []
    if isinstance(addrs, str):
        addrs = [a for a in re.split(r"[\s,]+", addrs) if a]
    for addr in addrs:
        ip = str(addr).split("/", 1)[0].strip()
        try:
            ver = ipaddress.ip_address(ip).version
        except ValueError:
            continue
        if ver == 4 and not v4:
            v4 = ip
        elif ver == 6 and not v6:
            v6 = ip
    if not v4:
        raise GenError("в конфиге нет IPv4-адреса (Address)")
    # Имя сервера — из комментария в секции [Peer] («# NL-FREE#123»);
    # комментарии [Interface] («# ROUTER») — не сервер.
    peer_part = re.split(r"(?im)^\s*\[Peer\]\s*$", text, maxsplit=1)
    m = _SERVER_COMMENT.search(peer_part[1]) if len(peer_part) > 1 else None
    name = m.group(1).strip() if m else ""
    return {
        "provider": "proton", "protocol": "wireguard", "source": "import",
        "service": "",
        "private_key": priv,
        "peer_public_key": pub,
        "ipv4": v4, "ipv6": v6 or ADDRESS_V6,
        "endpoint_host": host,
        "endpoint_port": int(port or cport or 51820),
        "reserved": [],
        "server": {"id": "", "name": name.replace("-FREE#", " #"),
                   "country": name[:2] if name else "", "city": "",
                   "load": 0, "entry_ip": host, "public_key": pub},
        "account": {"id": "", "type": "proton-import"},
        "warnings": [],
    }


def _is_wg_key(value: str) -> bool:
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def _split_endpoint(endpoint: str) -> tuple:
    endpoint = endpoint.strip()
    m = re.match(r"^\[([0-9A-Fa-f:.]+)\]:(\d+)$", endpoint) \
        or re.match(r"^([^\s:]+):(\d+)$", endpoint)
    if not m:
        raise GenError("в конфиге нет Endpoint вида адрес:порт")
    port = int(m.group(2))
    if not 1 <= port <= 65535:
        raise GenError("неверный порт в Endpoint")
    return m.group(1), port

