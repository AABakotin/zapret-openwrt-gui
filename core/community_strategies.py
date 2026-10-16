# core/community_strategies.py
"""
Стратегии сообщества по провайдеру (номеру AS): чтение открытой базы,
кандидаты подбора первыми, «Поделиться» / «Подтвердить» / «Не сработала».

## Зачем

Одна и та же коробка ТСПУ у одного провайдера режет одинаково: то, что
открыло сайт у соседа по провайдеру, у вас сработает с куда большей
вероятностью, чем случайный приём каталога. Наш ``core/strategy_memory``
помнит такое только локально. База nfqws2-ui (zemidala/nfqws2-strategies,
формат открытый) собирает находки абонентов по номеру AS — читаем её
(приём nfqws2-ui).

## Что берётся

* ``data/AS<номер>.json`` — стратегии своего провайдера (килобайты, при
  любом размере базы). Ответ помнится сутки, неудача — 10 минут; файла нет
  (404) — для провайдера пока ничего нет, это не ошибка.
* Из записи — только шаги ``--lua-desync`` по строгому шаблону
  (:data:`STEP_RE`: без путей и файлов); запись с чем-то ещё отбрасывается
  целиком. Перед подбором — наш линтер (неизвестная функция или blob —
  мимо).
* В подбор — до :data:`MAX` штук (:func:`candidates`): сначала подтверждённые
  за :data:`FRESH_DAYS` дней, среди них — открывавшие этот сайт, затем его
  сеть, затем по «подтвердили − не сработала»; «не сработала» у
  большинства (и хотя бы у двоих) не пробуется вовсе.

## Отправка

Ничего не уходит само. «Поделиться» (для своей находки), «Подтвердить» и
«Не сработала» (для взятой из базы) открывают предзаполненную форму
issue в репозитории базы (:func:`share_url`) — что уйдёт, видно целиком,
отправляет человек сам. Приём issue и модерация — на стороне базы.

## Провайдер

AS провайдера — ``community.asn``; пусто — определяется по внешнему
адресу через RIPEstat (``whats-my-ip`` → ``network-info``) и
запоминается в настройках. Сам адрес не сохраняется и не показывается.

Чистые функции (:func:`parse_items`, :func:`candidates`,
:func:`share_url`, …) отделены от сети.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.parse

from core.log_buffer import log

SOURCE = "community"

DEFAULT_REPO = "zemidala/nfqws2-strategies"
MAX = 8                 # сколько стратегий сообщества пробовать в подборе
FRESH_DAYS = 60         # подтверждалась позже — «свежая»
MAX_STEPS = 8
TTL_OK = 86400
TTL_ERROR = 600
FETCH_TIMEOUT = 20
# Шаг — только --lua-desync без путей и блобов из файлов; тот же шаблон
# проверяет и приём в репозитории базы.
STEP_RE = re.compile(
    r"^--lua-desync=[a-z][a-z0-9_]{0,40}(:[A-Za-z0-9_.,=+%-]{1,200}){0,40}$")
_TEXT_RE = re.compile(r"^[^\x00-\x1f<>`$\\]*")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
PROTOS = ("tls", "http")


# ─────────────────────────── чистые функции ───────────────────────────

def _text(value, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return _TEXT_RE.match(value).group(0)[:limit]


def parse_items(data, asn: int) -> list:
    """Ответ ``data/AS<asn>.json`` → проверенные записи.

    Данные из интернета: берётся только то, что подходит по формату.
    Запись с шагом не по шаблону, чужим AS или чужим протоколом
    отбрасывается целиком — урезанная стратегия была бы другой.
    """
    items = []
    for x in (data or {}).get("items") or [] if isinstance(data, dict) \
            else []:
        if not isinstance(x, dict):
            continue
        raw = x.get("steps")
        if not isinstance(raw, list) or not raw or len(raw) > MAX_STEPS:
            continue
        steps = [t for t in raw if isinstance(t, str) and STEP_RE.match(t)]
        if len(steps) != len(raw) or x.get("asn") != asn \
                or x.get("proto") not in PROTOS:
            continue
        targets = []
        for t in (x.get("targets") or [])[:30] \
                if isinstance(x.get("targets"), list) else []:
            if not isinstance(t, dict):
                continue
            host = t.get("host") if isinstance(t.get("host"), str) \
                and _HOST_RE.match(t.get("host").lower()) else None
            tasn = t.get("asn") if isinstance(t.get("asn"), int) else None
            if host or tasn:
                targets.append({k: v for k, v in (("host", host),
                                                  ("asn", tasn)) if v})

        def _int(key):
            try:
                return max(0, int(x.get(key) or 0))
            except (TypeError, ValueError):
                return 0
        items.append({
            "id": re.sub(r"[^0-9a-f]", "", _text(x.get("id"), 16)),
            "asn": asn, "provider": _text(x.get("provider"), 80),
            "proto": x["proto"], "steps": steps, "targets": targets,
            "reports": _int("reports") if "reports" in x else 1,
            "fails": _int("fails"),
            "first": _text(x.get("first"), 10),
            "last": _text(x.get("last"), 10),
            "nfqws2": _text(x.get("nfqws2"), 30),
        })
    return items


def fresh(item: dict, now: float = None) -> bool:
    """Подтверждалась ли за :data:`FRESH_DAYS` дней: DPI меняется."""
    try:
        t = time.mktime(time.strptime(str(item.get("last") or ""),
                                      "%Y-%m-%d"))
    except ValueError:
        return False
    return (now if now is not None else time.time()) - t \
        < FRESH_DAYS * 86400


def skipped(item: dict) -> bool:
    """«Не сработала» у большинства и хотя бы у двоих — не пробуем."""
    return item.get("fails", 0) >= 2 \
        and item.get("fails", 0) > item.get("reports", 0)


def candidates(items: list, host: str = "", host_asn: int = None,
               proto: str = "tls", now: float = None,
               limit: int = MAX) -> list:
    """Записи базы → кандидаты подбора, лучшие первыми.

    Порядок: свежие; среди них — открывавшие этот сайт, затем его сеть;
    затем «подтвердили − не сработала»; затем более поздние.
    """
    from core.custom_candidates import sid
    host = str(host or "").strip().lower()
    out = []
    for x in items or []:
        if x.get("proto") != proto or skipped(x):
            continue
        hosts = [t.get("host") for t in x.get("targets") or []]
        nets = [t.get("asn") for t in x.get("targets") or []]
        score = 2 if host and host in hosts else (
            1 if host_asn and host_asn in nets else 0)
        is_fresh = fresh(x, now)
        where = ("открывала %s" % host if score == 2 else
                 "работала в сети AS%s" % host_asn if score == 1 else
                 "AS%s" % x.get("asn"))
        desc = "сообщество: %s, подтвердили %d" % (where, x.get("reports", 0))
        if x.get("fails"):
            desc += ", не сработала у %d" % x["fails"]
        if not is_fresh:
            desc += ", давно не подтверждалась"
        out.append(((is_fresh, score, x.get("reports", 0) - x.get("fails", 0),
                     x.get("last") or ""), {
            "id": sid(list(x["steps"])), "args": list(x["steps"]),
            "name": "Сообщество: " + " ".join(
                s[len("--lua-desync="):].split(":", 1)[0]
                for s in x["steps"]),
            "description": desc, "label": "community",
            "source_file": "community:%s" % (x.get("id") or ""),
        }))
    out.sort(key=lambda p: p[0], reverse=True)
    return [c for _k, c in out[:limit]]


def steps_of(args) -> list:
    """Шаги ``--lua-desync`` из полной строки аргументов (без путей)."""
    if isinstance(args, str):
        args = args.split()
    return [a for a in args or [] if isinstance(a, str)
            and a.startswith("--lua-desync=")]


def share_url(repo: str, outcome: str, fields: dict) -> tuple:
    """Предзаполненная форма issue базы: (url, текст для показа).

    ``outcome`` — ``works`` (поделиться/подтвердить) или ``fails``.
    ``fields``: asn, provider, proto, target_host, target_asn, steps,
    result, nfqws2, ui, community (id записи базы — для подтверждения).
    """
    f = dict(fields or {})
    asn = re.sub(r"\D", "", str(f.get("asn") or ""))
    proto = f.get("proto") if f.get("proto") in PROTOS else "tls"
    steps = [s for s in f.get("steps") or [] if STEP_RE.match(str(s))]
    host = str(f.get("target_host") or "").strip().lower()
    host = host if _HOST_RE.match(host) else ""
    target_asn = re.sub(r"\D", "", str(f.get("target_asn") or ""))
    fail = outcome == "fails"
    prefix = "Не сработала · " if fail else (
        "Подтверждаю · " if f.get("community") else "")
    what = " · ".join(x for x in ("AS%s" % asn, proto, host or (
        steps[0][len("--lua-desync="):].split(":", 1)[0] if steps else ""))
        if x)
    query = {
        "template": "strategy.yml", "title": prefix + what,
        "outcome": "fails" if fail else "works", "asn": asn,
        "provider": _text(f.get("provider"), 80), "proto": proto,
        "target_host": host, "target_asn": target_asn,
        "strategy": "\n".join(steps), "result": _text(f.get("result"), 20),
        "nfqws2": _text(f.get("nfqws2"), 30), "ui": _text(f.get("ui"), 30),
    }
    repo = repo if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
                            str(repo or "")) else DEFAULT_REPO
    url = "https://github.com/%s/issues/new?%s" % (
        repo, urllib.parse.urlencode(query))
    text = "\n".join([
        "AS провайдера: %s%s" % (asn or "—", " · " + query["provider"]
                                 if query["provider"] else ""),
        "Протокол: %s" % proto,
        "Сайт: %s%s" % (host or "не указан",
                        " · сеть AS" + target_asn if target_asn else ""),
        "Результат: %s%s" % (query["result"] or "—",
                             " — не сработала" if fail else ""),
        "", query["strategy"]])
    return url, text


# ─────────────────────────────── сеть ───────────────────────────────

def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def repo() -> str:
    value = str(_cfg().get("community", "repo", default=DEFAULT_REPO) or "")
    return value if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", value) \
        else DEFAULT_REPO


def _get(url: str):
    """(код, тело) — через транспорт ``community.transport``.

    Соединение не состоялось (DNS роутера на секунду пропал) — ещё одна
    попытка через 3 секунды.
    """
    import urllib.error
    from core.download_transport import urlopen_via
    from core.version import GUI_VERSION
    transport = _cfg().get("community", "transport", default="") or ""
    last = None
    for attempt in range(2):
        if attempt:
            time.sleep(3)
        try:
            with urlopen_via(url, transport=transport,
                             timeout=FETCH_TIMEOUT,
                             headers={"User-Agent": "zapret-gui/%s"
                                      % GUI_VERSION}) as resp:
                return resp.status, resp.read(2 * 1024 * 1024)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception as e:                  # noqa: BLE001 — граница
            last = e
    raise OSError(str(last) or "нет соединения")


def _ripe(name: str, resource: str = "") -> dict:
    url = "https://stat.ripe.net/data/%s/data.json" % name
    if resource:
        url += "?resource=" + urllib.parse.quote(resource)
    code, body = _get(url)
    if code != 200:
        return {}
    try:
        return json.loads(body.decode("utf-8")).get("data") or {}
    except (ValueError, AttributeError):
        return {}


def ip_asn(ip: str) -> int:
    asns = _ripe("network-info", ip).get("asns") or []
    try:
        return int(asns[0])
    except (IndexError, TypeError, ValueError):
        return 0


def provider(detect: bool = False) -> dict:
    """AS провайдера: из настроек; ``detect`` — определить, если пусто."""
    cfg = _cfg()
    try:
        asn = int(cfg.get("community", "asn", default=0) or 0)
    except (TypeError, ValueError):
        asn = 0
    name = str(cfg.get("community", "provider", default="") or "")
    if asn or not detect:
        return {"asn": asn, "provider": name}
    try:
        ip = _ripe("whats-my-ip").get("ip")
        asn = ip_asn(ip) if ip else 0
        if asn:
            name = name or _text(_ripe("as-overview", "AS%d" % asn)
                                 .get("holder"), 80)
            cfg.set("community", "asn", asn)
            if name:
                cfg.set("community", "provider", name)
            cfg.save()
    except OSError as e:
        return {"asn": 0, "provider": name,
                "error": "провайдер не определён: %s" % e}
    return {"asn": asn, "provider": name,
            "error": "" if asn else "провайдер не определён"}


def host_asn(host: str) -> int:
    """Сеть сайта по первому адресу; заглушка, частный адрес — 0."""
    import ipaddress
    import socket
    try:
        ip = socket.getaddrinfo(host, 443, socket.AF_INET)[0][4][0]
        if not ipaddress.ip_address(ip).is_global:
            return 0
        return ip_asn(ip)
    except (OSError, ValueError, IndexError):
        return 0


def _cache_path(asn: int) -> str:
    return os.path.join(tempfile.gettempdir(),
                        "zapret-gui-community-AS%d.json" % asn)


def load(asn: int, force: bool = False) -> dict:
    """Записи базы для AS: {asn, items, fetched, checked, error}.

    Кеш — во временном каталоге (в RAM на роутере): после перезагрузки
    скачается заново.
    """
    path = _cache_path(asn)
    try:
        with open(path, "r", encoding="utf-8") as f:
            cached = json.load(f)
    except (OSError, ValueError):
        cached = {}
    if not isinstance(cached, dict) or cached.get("asn") != asn:
        cached = {"asn": asn, "items": [], "fetched": 0, "checked": 0,
                  "error": ""}
    ttl = TTL_ERROR if cached.get("error") else TTL_OK
    if not force and time.time() - cached.get("checked", 0) < ttl:
        return cached
    url = "https://raw.githubusercontent.com/%s/main/data/AS%d.json" % (
        repo(), asn)
    now = int(time.time())
    try:
        code, body = _get(url)
    except OSError as e:
        code, body = 0, b""
        cached.update(checked=now, error="база недоступна: %s" % e)
    if code == 404:
        cached = {"asn": asn, "items": [], "fetched": now, "checked": now,
                  "error": ""}
    elif code == 200:
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            data = None
        if isinstance(data, dict):
            cached = {"asn": asn, "items": parse_items(data, asn),
                      "fetched": now, "checked": now, "error": ""}
        else:
            cached.update(checked=now, error="база ответила не JSON")
    elif code:
        cached.update(checked=now, error="GitHub ответил %d" % code)
    try:
        from core.safe_io import atomic_write_json
        atomic_write_json(path, cached)
    except (OSError, TypeError, ValueError):
        pass
    return cached


def scan_candidates(host: str, proto: str = "tls") -> tuple:
    """Кандидаты подбора для сайта и что о базе сказать: (list, info).

    Сеть ходит здесь (RIPEstat, GitHub), поэтому зовётся только из
    фонового потока сканера и только когда пользователь включил базу.
    """
    from core import custom_candidates, lint_env
    prov = provider(detect=True)
    asn = prov.get("asn") or 0
    if not asn:
        return [], {"asn": 0, "count": 0,
                    "error": prov.get("error") or "провайдер не определён"}
    data = load(asn)
    mine = [x for x in data.get("items") or [] if x.get("proto") == proto]
    found = candidates(mine, host, host_asn(host) if mine else 0, proto)
    kf, kb = lint_env.known_functions(), lint_env.known_blobs()
    kept = [c for c in found
            if not custom_candidates.lint_reject(c["args"], kf, kb)]
    if len(kept) < len(found):
        log.info("Сообщество: %d стратегий не подходят этому устройству "
                 "(функции или блобы)" % (len(found) - len(kept)),
                 source=SOURCE)
    return kept, {"asn": asn, "count": len(mine),
                  "error": data.get("error") or ""}


def overview(force: bool = False, detect: bool = False) -> dict:
    """Что база знает о своём провайдере — для страницы."""
    prov = provider(detect=detect)
    asn = prov.get("asn") or 0
    out = {"asn": asn, "provider": prov.get("provider", ""),
           "repo": "https://github.com/%s" % repo(), "items": [],
           "error": prov.get("error") or ""}
    if not asn:
        return out
    data = load(asn, force=force)
    items = []
    for x in data.get("items") or []:
        items.append(dict(x, fresh=fresh(x), skipped=skipped(x)))
    items.sort(key=lambda x: (x["skipped"], not x["fresh"],
                              -(x["reports"] - x["fails"])))
    items_last = sorted(items, key=lambda x: x.get("last") or "",
                        reverse=True)
    out.update(items=items, fetched=data.get("fetched", 0),
               error=data.get("error") or out["error"],
               last=items_last[0]["last"] if items_last else "",
               page="https://github.com/%s/blob/main/providers/AS%d.md"
                    % (repo(), asn) if items else "")
    return out


def share(outcome: str, args, host: str = "", community: str = "",
          result: str = "", proto: str = "tls") -> dict:
    """Ссылка на предзаполненную issue и текст того, что в ней уйдёт."""
    from core.version import GUI_VERSION
    steps = steps_of(args)
    if not steps or len(steps) > MAX_STEPS \
            or not all(STEP_RE.match(s) for s in steps):
        return {"ok": False, "error": "в базу уходят только шаги "
                                      "--lua-desync без путей к файлам — у "
                                      "этой стратегии таких нет или есть "
                                      "лишнее"}
    prov = provider(detect=True)
    if not prov.get("asn"):
        return {"ok": False, "error": prov.get("error")
                or "провайдер не определён — впишите номер AS в настройке "
                   "community.asn"}
    nfqws2 = ""
    try:
        from core.zapret_installer import get_zapret_installer
        nfqws2 = str(get_zapret_installer().get_installed_version()
                     .get("version") or "")
    except Exception:                           # noqa: BLE001 — не важно
        pass
    host = str(host or "").strip().lower()
    url, text = share_url(repo(), outcome, {
        "asn": prov["asn"], "provider": prov.get("provider", ""),
        "proto": proto, "target_host": host,
        "target_asn": host_asn(host) if host else "",
        "steps": steps, "result": result, "nfqws2": nfqws2,
        "ui": "zapret-gui " + GUI_VERSION, "community": community})
    return {"ok": True, "url": url, "text": text}
