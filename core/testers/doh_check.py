# core/testers/doh_check.py
"""
Сверка DNS роутера с защищённым DNS (DoH): подмена и «закрытый адрес».

## Зачем

DNS-фаза blockcheck и раньше сверялась с DoH, но флажила подмену только
по очевидным признакам: заглушка, IP блок-страницы провайдера или
непубличный адрес. Публичный, но чужой адрес (провайдер увёл домен на
свою заглушку в интернете) и адрес, который DNS роутера выдал, а сеть
до него не пускает, проходили как «DNS в порядке» — и дальше подбор
стратегии гонялся за блокировкой, которой нет в DPI.

Здесь второй шаг (приём nfqws2-ui): если наборы адресов не пересекаются,
спрашиваем сеть, а не только DNS — открываются ли по TCP адреса роутера
и адреса из DoH. «Роутера — нет, DoH — да» значит, что лечится это DNS
(DoH/DoT, hosts), а не стратегией и не туннелем. Пересечение или «оба
открываются» — это CDN/гео-балансировка, а не подмена: молчим.

## Провайдеры

Яндекс первым: в РФ его DoH обычно доступен, когда Google и Cloudflare
закрыты или замедлены. Запрос — RFC 8484 в двоичном формате
(``application/dns-message``): JSON-вид есть не у всех, двоичный — у всех
трёх. Кодировщик и разборщик DNS-сообщения — свои, на stdlib.

Сеть здесь только в :func:`resolve` и :func:`reachable`; решение —
чистая :func:`verdict`, её и тестируем.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
import urllib.request
from typing import Any

PROVIDERS = (
    ("Яндекс", "https://common.dot.dns.yandex.net/dns-query"),
    ("Google", "https://dns.google/dns-query"),
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
)

USER_AGENT = "zapret-gui/doh-check"

QTYPE_A = 1
QTYPE_AAAA = 28


# ---------------------------------------------------------------------------
# DNS-сообщение (RFC 1035) — ровно столько, сколько нужно для A/AAAA
# ---------------------------------------------------------------------------

def build_query(name: str, qtype: int = QTYPE_A, qid: int | None = None) -> bytes:
    """DNS-запрос с одним вопросом и флагом RD."""
    name = (name or "").strip().rstrip(".")
    if not name:
        raise ValueError("пустое имя")
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for label in name.encode("idna").split(b"."):
        if not label or len(label) > 63:
            raise ValueError("неверное имя: %s" % name)
        qname += bytes([len(label)]) + label
    return header + qname + b"\x00" + struct.pack("!HH", qtype, 1)


def _skip_name(msg: bytes, pos: int) -> int:
    """Позиция сразу за именем (с учётом указателей сжатия)."""
    while True:
        if pos >= len(msg):
            raise ValueError("обрезанное имя")
        length = msg[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + length


def parse_answer(msg: bytes, qtype: int = QTYPE_A) -> list[str]:
    """Адреса нужного типа из ответа. Ошибка формата → ValueError."""
    if len(msg) < 12:
        raise ValueError("короткий ответ")
    _qid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    rcode = flags & 0x000F
    if rcode == 3:          # NXDOMAIN — ответ, а не ошибка
        return []
    if rcode != 0:
        raise ValueError("rcode %d" % rcode)
    pos = 12
    for _ in range(qd):
        pos = _skip_name(msg, pos) + 4
    ips: list[str] = []
    for _ in range(an):
        pos = _skip_name(msg, pos)
        if pos + 10 > len(msg):
            raise ValueError("обрезанная запись")
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
        pos += 10
        rdata = msg[pos:pos + rdlen]
        pos += rdlen
        if rtype == qtype == QTYPE_A and rdlen == 4:
            ips.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == qtype == QTYPE_AAAA and rdlen == 16:
            ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return ips


# ---------------------------------------------------------------------------
# Сеть
# ---------------------------------------------------------------------------

def _query(url: str, name: str, timeout: float) -> list[str]:
    req = urllib.request.Request(
        url, data=build_query(name), method="POST",
        headers={"Content-Type": "application/dns-message",
                 "Accept": "application/dns-message",
                 "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return parse_answer(resp.read(65535))


def resolve(name: str, timeout: float = 3.0, providers=PROVIDERS) -> dict:
    """A-записи имени через первый ответивший DoH-провайдер.

    Returns:
        {"ok", "ips", "provider", "error"} — ok=False, если не ответил ни
        один провайдер (DoH тоже бывает закрыт).
    """
    errors = []
    for label, url in providers:
        try:
            ips = _query(url, name, timeout)
        except Exception as e:                      # noqa: BLE001 — сеть
            errors.append("%s: %s" % (label, str(e)[:60]))
            continue
        return {"ok": True, "ips": ips, "provider": label, "error": ""}
    return {"ok": False, "ips": [], "provider": "",
            "error": "; ".join(errors) or "нет провайдеров"}


def reachable(ips, port: int = 443, timeout: float = 3.0,
              limit: int = 3) -> list[str]:
    """Какие из адресов принимают TCP-соединение (не больше ``limit``)."""
    from core import probe_mark
    ok = []
    for ip in list(ips or [])[:limit]:
        try:
            sock = probe_mark.create_connection((ip, port), timeout=timeout)
        except Exception:                           # noqa: BLE001 — сеть
            continue
        try:
            sock.close()
        except OSError:
            pass
        ok.append(ip)
    return ok


# ---------------------------------------------------------------------------
# Вердикт
# ---------------------------------------------------------------------------

def _public(ips) -> list[str]:
    out = []
    for ip in ips or []:
        try:
            if ipaddress.ip_address(str(ip)).is_global:
                out.append(str(ip))
        except ValueError:
            continue
    return out


def verdict(sys_ips, doh_ips, sys_open=None, doh_open=None) -> dict:
    """Решение по сверке. Чистая функция.

    Args:
        sys_ips: адреса от DNS роутера.
        doh_ips: адреса от DoH (пусто — DoH не ответил или NXDOMAIN).
        sys_open / doh_open: какие из них открываются по TCP; None —
            не проверяли (сверка без сети).

    Returns:
        {"kind": "match" | "differs" | "spoofed" | "closed_addr" |
                 "unknown", "fake": bool, "reason": str}

        ``spoofed`` — роутер отдал адрес, которого нет в DoH, и он не
        открывается, а адрес из DoH открывается: подмена DNS.
        ``closed_addr`` — то же, но адреса пересекаются частично
        (роутер выдал в том числе закрытый): лечится тоже DNS.
        ``differs`` — наборы разные, но оба открываются: CDN, не подмена.
    """
    sys_set = set(sys_ips or [])
    doh_set = set(doh_ips or [])
    if not sys_set or not doh_set:
        return {"kind": "unknown", "fake": False,
                "reason": "нечего сравнивать"}
    if sys_set <= doh_set:
        return {"kind": "match", "fake": False,
                "reason": "совпадает с DoH"}
    if sys_open is None or doh_open is None:
        return {"kind": "differs", "fake": False,
                "reason": "отличается от DoH (CDN или подмена — "
                          "без проверки соединения не понять)"}
    if not _public(doh_open):
        return {"kind": "differs", "fake": False,
                "reason": "адреса из DoH тоже не открываются — дело не в DNS"}
    if sys_open:
        return {"kind": "differs", "fake": False,
                "reason": "отличается от DoH, но открывается — CDN, не подмена"}
    kind = "spoofed" if sys_set.isdisjoint(doh_set) else "closed_addr"
    reason = ("DNS роутера выдаёт %s — не открывается, а адрес из DoH %s "
              "открывается" % (", ".join(sorted(sys_set)[:3]),
                               ", ".join(doh_open[:2])))
    return {"kind": kind, "fake": True, "reason": reason}


def cross_check(name: str, sys_ips, port: int = 443,
                timeout: float = 3.0) -> dict[str, Any]:
    """Сверка с DoH и, если наборы разные, — проверка соединения.

    Returns:
        verdict(...) плюс ``doh_ips``, ``provider``, ``doh_error``.
    """
    # DoH спрашиваем только про A — и сравниваем с A: IPv6 роутера с
    # IPv4 из DoH не пересекается никогда.
    sys_ips = [ip for ip in (sys_ips or []) if ":" not in str(ip)]
    doh = resolve(name, timeout=timeout)
    doh_ips = doh.get("ips") or []
    sys_open = doh_open = None
    if doh_ips and sys_ips and not set(sys_ips) <= set(doh_ips):
        sys_open = reachable(sys_ips, port=port, timeout=timeout)
        doh_open = [] if sys_open else reachable(
            [ip for ip in doh_ips if ip not in set(sys_ips)],
            port=port, timeout=timeout)
    out = verdict(sys_ips, doh_ips, sys_open, doh_open)
    out.update(doh_ips=doh_ips, provider=doh.get("provider", ""),
               doh_error=doh.get("error", ""))
    return out
