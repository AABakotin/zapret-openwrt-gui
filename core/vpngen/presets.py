# core/vpngen/presets.py
"""
Пресеты генератора: DNS, адреса Cloudflare, маски обфускации, AllowedIPs.

Всё здесь — данные, а не логика: UI показывает их как списки выбора,
MCP отдаёт через ``vpngen_options``, а генератор подставляет в конфиг.
Поменять список — значит поменять только этот файл.

Про обфускацию и серверы WARP/Proton. И Cloudflare WARP, и Proton —
это ОБЫЧНЫЙ WireGuard на стороне сервера. С ванильным пиром совместима
только та часть AmneziaWG, что живёт на клиенте (скил ``awg`` §2.1):

* junk-пакеты ``Jc/Jmin/Jmax`` — отдельные датаграммы перед рукопожатием,
  которые сервер молча выбрасывает;
* signature-пакеты ``I1..I5`` — то же самое, но с содержимым, похожим на
  другой протокол (QUIC Initial, SIP, DNS): DPI видит начало «чужого»
  протокола и пропускает поток.

``S1..S4 != 0`` и ``H1..H4 != 1..4`` меняют формат самих пакетов
WireGuard — Cloudflare и Proton их не разберут, туннель не поднимется.
Поэтому эти параметры генератор не трогает вовсе.
"""

from __future__ import annotations

import ipaddress
import secrets
import struct

# ─────────────────────────────── DNS ─────────────────────────────────

DNS_PRESETS = [
    {"id": "cloudflare", "label": "Cloudflare (1.1.1.1)",
     "v4": ["1.1.1.1", "1.0.0.1"],
     "v6": ["2606:4700:4700::1111", "2606:4700:4700::1001"]},
    {"id": "google", "label": "Google (8.8.8.8)",
     "v4": ["8.8.8.8", "8.8.4.4"],
     "v6": ["2001:4860:4860::8888", "2001:4860:4860::8844"]},
    {"id": "quad9", "label": "Quad9 (9.9.9.9)",
     "v4": ["9.9.9.9", "149.112.112.112"],
     "v6": ["2620:fe::fe", "2620:fe::9"]},
    {"id": "adguard", "label": "AdGuard (без рекламы)",
     "v4": ["94.140.14.14", "94.140.15.15"],
     "v6": ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"]},
    {"id": "comss", "label": "Comss.one (разблокирует ИИ-сервисы)",
     "v4": ["83.220.169.155", "212.109.195.93"],
     "v6": ["2a01:230:4:915::2"]},
    # DNS самого провайдера VPN: у Proton свой резолвер внутри туннеля.
    {"id": "provider", "label": "DNS провайдера VPN",
     "v4": [], "v6": []},
]

PROTON_DNS = {"v4": ["10.2.0.1"], "v6": ["2a07:b944::2:1"]}


def dns_servers(preset: str, *, ipv6: bool, provider: str = "warp",
                custom=None) -> list:
    """Список DNS для ``[Interface] DNS``.

    ``custom`` — список строк от пользователя; ``preset="provider"`` у
    WARP значит Cloudflare (у WARP нет «своего» резолвера в туннеле).
    """
    if preset == "custom":
        out = []
        for item in custom or []:
            ip = str(item).strip()
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version == 6 and not ipv6:
                continue
            out.append(ip)
        return out or ["1.1.1.1"]
    if preset == "provider" and provider == "proton":
        entry = PROTON_DNS
    else:
        entry = next((p for p in DNS_PRESETS if p["id"] == preset), None)
        if entry is None or not entry["v4"]:
            entry = DNS_PRESETS[0]
    return list(entry["v4"]) + (list(entry["v6"]) if ipv6 else [])


# ───────────────────────── Cloudflare endpoints ──────────────────────
#
# Только адреса самой Cloudflare. Сторонние «ретрансляторы» WARP, которые
# встречаются в чужих генераторах (сервер энтузиаста, пересылающий UDP в
# Cloudflare), сюда не входят: через них идёт весь трафик пользователя,
# а кто их держит и что они пишут в лог — неизвестно.

WARP_ENDPOINT_HOST = "engage.cloudflareclient.com"
WARP_ENDPOINT_PORT = 2408

WARP_IP_PREFIXES = (
    "162.159.192.", "162.159.195.",
    "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.",
    "8.6.112.", "8.34.70.", "8.34.146.", "8.35.211.", "8.39.125.",
    "8.39.204.", "8.39.214.", "8.47.69.",
)

# Порты, на которых отвечает WARP (WireGuard). 2408 — штатный; остальные
# выручают, когда провайдер режет именно его.
WARP_PORTS = (500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928,
              934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010,
              1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408,
              2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279,
              5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886)

ENDPOINT_MODES = [
    {"id": "account", "label": "Как выдал Cloudflare (engage…:2408)"},
    {"id": "random", "label": "Случайный адрес и порт Cloudflare"},
    {"id": "custom", "label": "Свой адрес:порт"},
]


def random_warp_endpoint() -> tuple:
    """Случайный ``(host, port)`` из адресов и портов Cloudflare WARP."""
    prefix = secrets.choice(WARP_IP_PREFIXES)
    return "%s%d" % (prefix, 1 + secrets.randbelow(10)), \
        secrets.choice(WARP_PORTS)


# MASQUE-эндпоинт приходит в ответе регистрации (endpoint_v4). Этот —
# на случай, если ответ неполный: он же зашит в usque как дефолт H2.
MASQUE_ENDPOINT_V4 = "162.159.198.2"
MASQUE_PORT = 443

# Порты, на которых Proton принимает WireGuard.
PROTON_PORTS = (51820, 443, 88, 80, 500, 1194, 1224, 4500, 4569, 5060)

# ─────────────────────────────── AllowedIPs ──────────────────────────

_PRIVATE_V4 = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
               "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
               "224.0.0.0/3")


def _exclude(base: str, holes) -> list:
    nets = [ipaddress.ip_network(base)]
    for hole in holes:
        hole = ipaddress.ip_network(hole)
        out = []
        for net in nets:
            if hole.subnet_of(net):
                out.extend(net.address_exclude(hole))
            elif not net.subnet_of(hole):
                out.append(net)
        nets = out
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


ALLOWED_PRESETS = [
    {"id": "all", "label": "Весь трафик (0.0.0.0/0, ::/0)"},
    {"id": "public", "label": "Весь, кроме локальных сетей"},
    {"id": "custom", "label": "Свой список подсетей"},
]


def allowed_ips(preset: str, *, ipv6: bool, custom=None) -> list:
    if preset == "public":
        out = _exclude("0.0.0.0/0", _PRIVATE_V4)
        if ipv6:
            out += _exclude("::/0", ("fc00::/7", "fe80::/10", "ff00::/8"))
        return out
    if preset == "custom":
        out = []
        for item in custom or []:
            try:
                net = ipaddress.ip_network(str(item).strip(), strict=False)
            except ValueError:
                continue
            if net.version == 6 and not ipv6:
                continue
            out.append(str(net))
        if out:
            return out
    return ["0.0.0.0/0", "::/0"] if ipv6 else ["0.0.0.0/0"]


# ─────────────────────────── маски (I1..I5) ──────────────────────────

# Крупные российские сайты: QUIC Initial «к ним» DPI пропускает.
QUIC_SNI_DOMAINS = (
    "ozon.ru", "wildberries.ru", "avito.ru", "gosuslugi.ru", "vk.com",
    "mail.ru", "rutube.ru", "kinopoisk.ru", "2gis.ru", "dzen.ru",
    "sberbank.ru", "tbank.ru", "rbc.ru", "ria.ru", "hh.ru", "kp.ru",
    "lenta.ru", "drom.ru", "auto.ru", "cdek.ru",
)

# SIP INVITE и ответ «100 Trying» (пример из RFC 3261) — две
# signature-датаграммы, похожие на начало VoIP-звонка.
_SIP_INVITE = (
    "INVITE sip:bob@biloxi.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n"
    "Max-Forwards: 70\r\nTo: Bob <sip:bob@biloxi.com>\r\n"
    "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\nCSeq: 314159 INVITE\r\n"
    "Contact: <sip:alice@pc33.atlanta.com>\r\n"
    "Content-Type: application/sdp\r\nContent-Length: 0\r\n\r\n")
_SIP_TRYING = (
    "SIP/2.0 100 Trying\r\n"
    "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n"
    "To: Bob <sip:bob@biloxi.com>\r\n"
    "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\nCSeq: 314159 INVITE\r\n"
    "Content-Length: 0\r\n\r\n")

MASK_PROFILES = [
    {"id": "none", "label": "Без маски (только junk-пакеты)"},
    {"id": "quic", "label": "QUIC: как подключение браузера к сайту"},
    {"id": "dns", "label": "DNS-запрос к сайту"},
    {"id": "sip", "label": "SIP: начало VoIP-звонка"},
    {"id": "custom", "label": "Свой I1 (<b 0x…>, <r N> …)"},
]


def blob(raw: bytes) -> str:
    return "<b 0x%s>" % raw.hex()


def quic_mask(sni: str, *, full: bool = True) -> str:
    """I1 — настоящий QUIC Initial с ClientHello для ``sni``.

    Шифрование Initial-ключами (RFC 9001) берём из проб DPI
    (``core.testers.quic_initial``): DPI расшифровывает такой пакет и
    видит имя сайта, ровно как у браузера. ``full=False`` — без PADDING
    до 1200 байт: короче, но формально не по RFC 9000 §14.1.
    """
    from core.testers import quic_initial as qi

    if full:
        packet, _dcid, _scid = qi.build_initial(sni)
        return blob(packet)
    dcid = secrets.token_bytes(8)
    scid = secrets.token_bytes(8)
    hello = qi.build_client_hello(sni, scid)
    crypto = b"\x06" + qi._varint(0) + qi._varint(len(hello)) + hello
    return blob(qi.protect_initial(dcid, scid, crypto))


def dns_mask(domain: str) -> str:
    """I1 — DNS-запрос A-записи ``domain`` (как от обычного резолвера)."""
    qname = b"".join(bytes([len(p)]) + p.encode("idna")
                     for p in domain.strip(".").split(".")) + b"\x00"
    header = struct.pack(">HHHHHH", secrets.randbelow(0x10000), 0x0100,
                         1, 0, 0, 0)
    return blob(header + qname + struct.pack(">HH", 1, 1))


def masks(profile: str, *, sni: str = "", custom: str = "",
          full_quic: bool = True) -> dict:
    """``{"I1": …, "I2": …}`` для профиля маски (пусто — без маски)."""
    profile = (profile or "none").strip()
    domain = (sni or "").strip() or secrets.choice(QUIC_SNI_DOMAINS)
    if profile == "quic":
        return {"I1": quic_mask(domain, full=full_quic)}
    if profile == "dns":
        return {"I1": dns_mask(domain)}
    if profile == "sip":
        return {"I1": blob(_SIP_INVITE.encode()),
                "I2": blob(_SIP_TRYING.encode())}
    if profile == "custom" and custom.strip():
        value = " ".join(custom.split())
        if value.upper().startswith("I1"):
            value = value.split("=", 1)[-1].strip()
        if not value.startswith("<"):
            raise ValueError("I1 — последовательность тегов вида"
                             " <b 0xHEX>, <r N>, <t>")
        return {"I1": value}
    return {}


JUNK_PRESETS = [
    # Для WARP — то, что используют рабочие конфиги «в дикой природе».
    {"id": "light", "label": "Лёгкий (4 пакета 40–70 байт)",
     "Jc": 4, "Jmin": 40, "Jmax": 70},
    {"id": "medium", "label": "Средний (8 пакетов 50–1000 байт)",
     "Jc": 8, "Jmin": 50, "Jmax": 1000},
    {"id": "heavy", "label": "Сильный (30 пакетов 10–30 байт)",
     "Jc": 30, "Jmin": 10, "Jmax": 30},
    {"id": "off", "label": "Без junk (чистый WireGuard)",
     "Jc": 0, "Jmin": 0, "Jmax": 0},
]


def junk(preset: str) -> dict:
    entry = next((p for p in JUNK_PRESETS if p["id"] == preset),
                 JUNK_PRESETS[0])
    return {k: entry[k] for k in ("Jc", "Jmin", "Jmax")}
