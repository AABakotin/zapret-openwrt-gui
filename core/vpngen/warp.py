# core/vpngen/warp.py
"""
Cloudflare WARP: регистрация устройства под WireGuard и под MASQUE.

Два источника:

* ``native`` (по умолчанию) — роутер сам говорит с API Cloudflare
  (``api.cloudflareclient.com``) ровно так, как это делает usque
  (``api/cloudflare.go``): те же версия API, заголовки и тела. Ключи
  генерируются здесь же (``core.vpngen.keys``), наружу уходит только
  публичный ключ.
* ``service`` — готовый сервис-генератор (зеркала warp-generation),
  который регистрирует устройство у себя и отдаёт ключи. Нужен там, где
  Cloudflare API недоступен, а обхода ещё нет. Цена — приватный ключ
  создан чужим сервером: в UI это сказано прямо.

Результат — «профиль»: плоский словарь с тем, что нужно рендерам
(``core.vpngen.render``) любого движка.
"""

from __future__ import annotations

import base64
import secrets
import time

from core.log_buffer import log
from core.vpngen import keys
from core.vpngen import presets
from core.vpngen.net import GenError, request_json

API = "https://api.cloudflareclient.com"
# Версия API и заголовки — как у usque v4.2.1 (internal/consts.go): с ними
# Cloudflare переключает устройство на MASQUE; WireGuard-регистрация
# через ту же версию даёт обычный WARP-аккаунт.
API_VERSION = "v0a4471"
HEADERS = {
    "User-Agent": "WARP for Android",
    "CF-Client-Version": "a-6.35-4471",
    "Content-Type": "application/json; charset=UTF-8",
}

# Сервисы-генераторы (ответ: privKey, peer_pub, client_ipv4, client_ipv6).
# Те же, к которым обращается warp-generation.github.io.
SERVICE_WG = (
    "https://warp-workers.warp-api.cfd",
    "https://warp-sub.warp-api.cfd",
    "https://warp-vercel-chi.warp-api.cfd",
    "https://warp-netlify.warp-api.cfd",
)
SERVICE_MASQUE = (
    "https://masque-workers.warp-api.cfd",
    "https://masque-vercel.warp-api.cfd",
)


def _cf_time() -> str:
    """Время в формате, который ждёт Cloudflare (как TimeAsCfString)."""
    return time.strftime("%Y-%m-%dT%H:%M:%S.000+00:00", time.gmtime())


def _unwrap(resp) -> dict:
    """Ответ Cloudflare бывает и плоским, и в ``result``."""
    if isinstance(resp, dict) and isinstance(resp.get("result"), dict):
        return resp["result"]
    return resp if isinstance(resp, dict) else {}


def _register(public_key_b64: str, transport: str, *, model: str = "PC",
              jwt: str = "") -> dict:
    body = {
        "key": public_key_b64,
        "install_id": "",
        "fcm_token": "",
        "tos": _cf_time(),
        "model": model,
        "serial_number": secrets.token_hex(8),
        "os_version": "",
        "key_type": "curve25519",
        "tunnel_type": "wireguard",
        "locale": "en_US",
    }
    headers = dict(HEADERS)
    if jwt:
        headers["CF-Access-Jwt-Assertion"] = jwt
    acc = _unwrap(request_json("POST", "%s/%s/reg" % (API, API_VERSION),
                               body=body, headers=headers,
                               transport=transport))
    if not acc.get("id") or not acc.get("token"):
        raise GenError("Cloudflare не выдал id/token устройства")
    return acc


def _auth(token: str) -> dict:
    headers = dict(HEADERS)
    headers["Authorization"] = "Bearer %s" % token
    return headers


def _apply_license(acc: dict, license_key: str, transport: str) -> list:
    """WARP+ ключ на свежий аккаунт. Неудача — предупреждение, не ошибка."""
    if not license_key:
        return []
    url = "%s/%s/reg/%s/account" % (API, API_VERSION, acc["id"])
    try:
        request_json("PUT", url, body={"license": license_key},
                     headers=_auth(acc["token"]), transport=transport)
        info = _unwrap(request_json("GET", url, headers=_auth(acc["token"]),
                                    transport=transport))
        acc.setdefault("account", {}).update(
            {k: info[k] for k in ("account_type", "warp_plus",
                                  "premium_data", "quota") if k in info})
    except GenError as e:
        return ["WARP+ ключ не применён: %s" % e]
    return []


def _peer(acc: dict) -> dict:
    peers = ((acc.get("config") or {}).get("peers") or [{}])
    return peers[0] or {}


def _addresses(acc: dict) -> tuple:
    addrs = ((acc.get("config") or {}).get("interface") or {}).get(
        "addresses") or {}
    return str(addrs.get("v4") or ""), str(addrs.get("v6") or "")


def _strip_port(value: str) -> str:
    """``162.159.192.1:0`` → ``162.159.192.1``; ``[2606::1]:0`` → ``2606::1``."""
    v = str(value or "").strip()
    if v.startswith("["):
        return v[1:v.find("]")] if "]" in v else v.strip("[]")
    if v.count(":") == 1:
        return v.split(":", 1)[0]
    return v


def _reserved(acc: dict) -> list:
    """client_id → три байта ``reserved`` (нужны sing-box/mihomo для WARP)."""
    cid = (acc.get("config") or {}).get("client_id") or ""
    try:
        raw = base64.b64decode(cid)
    except (ValueError, TypeError):
        return []
    return list(raw[:3]) if len(raw) >= 3 else []


def _account_summary(acc: dict) -> dict:
    info = acc.get("account") or {}
    return {
        "id": acc.get("id", ""),
        "type": info.get("account_type") or "free",
        "warp_plus": bool(info.get("warp_plus")),
        "premium_data": info.get("premium_data") or 0,
    }


# ───────────────────────────── WireGuard ─────────────────────────────

def wireguard_native(transport: str, *, license_key: str = "") -> dict:
    priv, pub = keys.x25519_keypair()
    log.info("vpngen: регистрация WARP (WireGuard) через %s" % transport,
             source="vpngen")
    acc = _register(pub, transport)
    warnings = _apply_license(acc, license_key.strip(), transport)
    peer = _peer(acc)
    v4, v6 = _addresses(acc)
    host = presets.WARP_ENDPOINT_HOST
    port = presets.WARP_ENDPOINT_PORT
    ep = (peer.get("endpoint") or {}).get("host") or ""
    if ep and ":" in ep and not ep.startswith("["):
        h, _, p = ep.rpartition(":")
        if h and p.isdigit() and 0 < int(p) < 65536:
            host, port = h, int(p)
    return {
        "provider": "warp", "protocol": "wireguard", "source": "native",
        "private_key": priv,
        "peer_public_key": peer.get("public_key")
        or "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "ipv4": v4 or "172.16.0.2", "ipv6": v6,
        "endpoint_host": host, "endpoint_port": port,
        "reserved": _reserved(acc),
        "account": _account_summary(acc),
        "warnings": warnings,
    }


def wireguard_service(transport: str) -> dict:
    data, used = _from_service(SERVICE_WG, transport)
    for key in ("privKey", "peer_pub", "client_ipv4"):
        if not data.get(key):
            raise GenError("сервис-генератор не вернул %s" % key)
    return {
        "provider": "warp", "protocol": "wireguard", "source": "service",
        "service": used,
        "private_key": data["privKey"],
        "peer_public_key": data["peer_pub"],
        "ipv4": data["client_ipv4"], "ipv6": data.get("client_ipv6") or "",
        "endpoint_host": presets.WARP_ENDPOINT_HOST,
        "endpoint_port": presets.WARP_ENDPOINT_PORT,
        "reserved": [],
        "account": {"id": "", "type": "free", "warp_plus": False},
        "warnings": ["Ключи создал сервис-генератор %s: приватный ключ"
                     " известен ему. Для своего ключа — источник"
                     " «Напрямую в Cloudflare»." % used],
    }


# ────────────────────────────── MASQUE ───────────────────────────────

def masque_native(transport: str, *, device_name: str = "",
                  license_key: str = "", jwt: str = "") -> dict:
    """Регистрация + переключение устройства на MASQUE (как ``usque register``).

    Cloudflare требует сначала зарегистрировать устройство с ключом
    curve25519 — usque шлёт туда СЛУЧАЙНЫЕ 32 байта, ключ WireGuard не
    используется. Потом PATCH меняет ключ на P-256 и тип туннеля на
    MASQUE.
    """
    log.info("vpngen: регистрация WARP (MASQUE) через %s" % transport,
             source="vpngen")
    acc = _register(keys.b64(secrets.token_bytes(32)), transport, jwt=jwt)
    warnings = _apply_license(acc, license_key.strip(), transport)
    pair = keys.p256_keypair()
    update = {"key": pair["public_der_b64"], "key_type": "secp256r1",
              "tunnel_type": "masque"}
    if device_name:
        update["name"] = device_name
    enrolled = _unwrap(request_json(
        "PATCH", "%s/%s/reg/%s" % (API, API_VERSION, acc["id"]),
        body=update, headers=_auth(acc["token"]), transport=transport))
    peer = _peer(enrolled)
    ep = peer.get("endpoint") or {}
    v4, v6 = _addresses(enrolled)
    if not peer.get("public_key"):
        raise GenError("Cloudflare не вернул ключ MASQUE-сервера")
    return {
        "provider": "warp", "protocol": "masque", "source": "native",
        "private_key": pair["private_der_b64"],
        "endpoint_pub_key": peer["public_key"],
        "endpoint_v4": _strip_port(ep.get("v4")) or presets.MASQUE_ENDPOINT_V4,
        "endpoint_v6": _strip_port(ep.get("v6")),
        "id": acc["id"], "access_token": acc["token"],
        "ipv4": v4, "ipv6": v6,
        "account": _account_summary(dict(acc, **{
            "account": enrolled.get("account") or acc.get("account")})),
        "warnings": warnings,
    }


def masque_service(transport: str) -> dict:
    data, used = _from_service(SERVICE_MASQUE, transport)
    for key in ("privKey", "peer_pub", "client_ipv4"):
        if not data.get(key):
            raise GenError("сервис-генератор не вернул %s" % key)
    pub = keys.pem_body(data["peer_pub"])
    pem = "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % "\n".join(
        pub[i:i + 64] for i in range(0, len(pub), 64))
    return {
        "provider": "warp", "protocol": "masque", "source": "service",
        "service": used,
        "private_key": data["privKey"],
        "endpoint_pub_key": pem,
        "endpoint_v4": presets.MASQUE_ENDPOINT_V4, "endpoint_v6": "",
        # Сервис не отдаёт учётку устройства. Туннелю usque она не нужна
        # (соединение аутентифицирует ключ P-256), но без неё не работают
        # `usque account`/`enroll`.
        "id": "service", "access_token": "service",
        "ipv4": data["client_ipv4"], "ipv6": data.get("client_ipv6") or "",
        "account": {"id": "", "type": "free", "warp_plus": False},
        "warnings": ["Ключи создал сервис-генератор %s: приватный ключ"
                     " известен ему, а учётки устройства нет (usque"
                     " account/enroll не сработают)." % used],
    }


def _from_service(urls, transport: str) -> tuple:
    errors = []
    for url in urls:
        try:
            data = request_json("GET", url, transport=transport, retries=1,
                                headers={"X-Client": "WARP"})
        except GenError as e:
            errors.append("%s — %s" % (url, e))
            continue
        if isinstance(data, dict) and data.get("privKey"):
            return data, url
        errors.append("%s — неожиданный ответ" % url)
    raise GenError("ни один сервис-генератор не ответил: %s"
                   % "; ".join(errors), network=True)


def generate(protocol: str, source: str, transport: str, **kw) -> dict:
    if protocol == "masque":
        if source == "service":
            return masque_service(transport)
        return masque_native(transport, device_name=kw.get("device_name", ""),
                             license_key=kw.get("license_key", ""),
                             jwt=kw.get("jwt", ""))
    if source == "service":
        return wireguard_service(transport)
    return wireguard_native(transport, license_key=kw.get("license_key", ""))
