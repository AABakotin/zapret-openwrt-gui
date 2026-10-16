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
(DoH/DoT, hosts): адрес от DNS роутера закрыт. Это не всегда подмена —
так же выглядит блок по IP одного узла CDN, который выдаёт провайдерский
резолвер, — но лекарство одно: другой DNS даёт открытый узел. Пересечение
или «оба открываются» — это CDN/гео-балансировка: молчим.

Чего здесь НЕ ловится: публичная заглушка провайдера, которая принимает
TCP. По соединению её от CDN не отличить — нужен TLS с проверкой
сертификата, а это уже работа пробы (``core/testers/probe.py``).

Сверка только в разовом тесте (blockcheck): до девяти сетевых операций
на домен — фоновому мониторингу по сотням доменов (block_detector) это
не по карману, он остаётся на однозначных признаках из ``probe.py``.

## Провайдеры

Google и Cloudflare первыми, Яндекс — запасным: российский резолвер
обязан следовать реестру блокировок и для заблокированного домена может
ответить так же, как провайдер, — эталоном он быть не может. Но в РФ его
DoH обычно доступен, когда Google и Cloudflare закрыты, и для домена вне
реестра (а «DNS выдаёт закрытый адрес» — как раз про такие) он годится.
Пустой ответ (NXDOMAIN, нет A-записей) — повод спросить следующего.

Запрос — RFC 8484 в двоичном формате (``application/dns-message``):
JSON-вид есть не у всех, двоичный — у всех трёх. Отдельно от
``core/routing/doh_resolver`` намеренно: тот только JSON и включается
настройкой ``routing.doh.enabled`` для маршрутизации, а диагностике
DoH нужен всегда.

Сеть здесь только в :func:`resolve` и :func:`reachable`; решение —
чистая :func:`verdict`, её и тестируем.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
import urllib.request
from typing import Any

PROVIDERS = (
    ("Google", "https://dns.google/dns-query"),
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("Яндекс", "https://common.dot.dns.yandex.net/dns-query"),
)

# Бюджет одной сверки, секунд: DNS-фаза идёт по списку доменов
# последовательно, и закрытые адреса не должны растягивать её на минуты.
BUDGET = 8.0

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


def resolve(name: str, timeout: float = 3.0, providers=PROVIDERS,
            deadline: float | None = None) -> dict:
    """A-записи имени через первого DoH-провайдера с непустым ответом.

    Returns:
        {"ok", "ips", "provider", "error"} — ok=False, если не ответил ни
        один провайдер (DoH тоже бывает закрыт); ok=True и пустой ``ips`` —
        все ответившие сказали «такого адреса нет».
    """
    errors = []
    answered = ""
    for label, url in providers:
        left = _left(deadline, timeout)
        if left <= 0:
            errors.append("бюджет времени исчерпан")
            break
        try:
            ips = _query(url, name, left)
        except Exception as e:                      # noqa: BLE001 — сеть
            errors.append("%s: %s" % (label, str(e)[:60]))
            continue
        if ips:
            return {"ok": True, "ips": ips, "provider": label, "error": ""}
        answered = answered or label
    if answered:
        return {"ok": True, "ips": [], "provider": answered, "error": ""}
    return {"ok": False, "ips": [], "provider": "",
            "error": "; ".join(errors) or "нет провайдеров"}


def _left(deadline, timeout: float) -> float:
    """Сколько можно ждать следующую операцию: таймаут, но не за дедлайн."""
    if deadline is None:
        return timeout
    return min(timeout, deadline - time.monotonic())


def reachable(ips, port: int = 443, timeout: float = 3.0,
              limit: int = 6, deadline: float | None = None,
              first: bool = False) -> list[str]:
    """Какие из адресов принимают TCP-соединение (не больше ``limit``).

    ``first=True`` — остановиться на первом открытом: для вердикта важно
    «есть ли открытый», а не сколько их.
    """
    from core import probe_mark
    ok = []
    for ip in list(ips or [])[:limit]:
        left = _left(deadline, timeout)
        if left <= 0:
            break
        try:
            sock = probe_mark.create_connection((ip, port), timeout=left)
        except Exception:                           # noqa: BLE001 — сеть
            continue
        try:
            sock.close()
        except OSError:
            pass
        ok.append(ip)
        if first:
            break
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
        {"kind": "match" | "differs" | "closed_addr" | "unknown",
         "fake": bool, "reason": str}

        ``closed_addr`` (fake=True) — у роутера и DoH нет ни одного общего
        адреса, адреса роутера не открываются, а из DoH открываются:
        подмена DNS или блок по IP узла, который выдаёт провайдерский
        резолвер. Лечится сменой DNS.
        ``differs`` — наборы разные, но адреса роутера открываются (CDN),
        или открытых нет ни у кого, или наборы пересекаются (общий адрес
        DoH подтверждает — это не подмена).
    """
    sys_set = set(sys_ips or [])
    doh_set = set(doh_ips or [])
    if not sys_set or not doh_set:
        return {"kind": "unknown", "fake": False,
                "reason": "нечего сравнивать"}
    if sys_set <= doh_set:
        return {"kind": "match", "fake": False,
                "reason": "совпадает с DoH"}
    if not sys_set.isdisjoint(doh_set):
        return {"kind": "differs", "fake": False,
                "reason": "частично совпадает с DoH — не подмена"}
    if sys_open is None or doh_open is None:
        return {"kind": "differs", "fake": False,
                "reason": "отличается от DoH (CDN или подмена — "
                          "без проверки соединения не понять)"}
    if sys_open:
        return {"kind": "differs", "fake": False,
                "reason": "отличается от DoH, но открывается — CDN, не подмена"}
    if not _public(doh_open):
        return {"kind": "differs", "fake": False,
                "reason": "адреса из DoH тоже не открываются — дело не в DNS"}
    reason = ("DNS роутера выдаёт закрытый адрес (%s), а адрес из DoH (%s) "
              "открывается — поможет другой DNS (DoH/DoT)"
              % (", ".join(sorted(sys_set)[:3]), ", ".join(doh_open[:2])))
    return {"kind": "closed_addr", "fake": True, "reason": reason}


def cross_check(name: str, sys_ips, port: int = 443,
                timeout: float = 2.0, budget: float = BUDGET) -> dict[str, Any]:
    """Сверка с DoH и, если наборы не пересекаются, — проверка соединения.

    Укладывается в ``budget`` секунд (не успели проверить соединение —
    вердикт ``differs`` без обвинений).

    Returns:
        verdict(...) плюс ``doh_ips``, ``provider``, ``doh_error``.
    """
    deadline = time.monotonic() + budget
    # DoH спрашиваем только про A — и сравниваем с A: IPv6 роутера с
    # IPv4 из DoH не пересекается никогда.
    sys_ips = [ip for ip in (sys_ips or []) if ":" not in str(ip)]
    doh = resolve(name, timeout=timeout, deadline=deadline)
    doh_ips = doh.get("ips") or []
    sys_open = doh_open = None
    if doh_ips and sys_ips and set(sys_ips).isdisjoint(doh_ips):
        sys_open = reachable(sys_ips, port=port, timeout=timeout,
                             deadline=deadline, first=True)
        if not sys_open:
            doh_open = reachable(doh_ips, port=port, timeout=timeout,
                                 deadline=deadline, first=True)
            # Не успели проверить все адреса роутера — обвинять DNS рано.
            if time.monotonic() >= deadline:
                sys_open = doh_open = None
        else:
            doh_open = []
    out = verdict(sys_ips, doh_ips, sys_open, doh_open)
    out.update(doh_ips=doh_ips, provider=doh.get("provider", ""),
               doh_error=doh.get("error", ""))
    return out
