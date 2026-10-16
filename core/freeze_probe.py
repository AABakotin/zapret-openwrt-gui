# core/freeze_probe.py
"""
Проба «обрыв на 16 КБ» по сетям хостингов: какое имя в фейке снимает обрыв.

## Зачем

ТСПУ режет соединения с адресами хостингов (Hetzner, OVH, DigitalOcean,
Contabo, Oracle, Cloudflare…) не по имени сайта, а по объёму: первые
16–20 КБ проходят, дальше тишина или RST. ``core/testers/tcp_test.py``
такой обрыв видит, но не лечит. Лечит его обычно фейк с «безопасным»
именем — сайтом, который провайдер не трогает (приём nfqws2-ui; имена и
приёмы — по замерам z2k и dpi-detector, MIT).

Здесь:

1. **Без обхода** — по одному адресу от каждой сети из
   ``data/tcp_targets.json`` (у записи есть ``asn``) качается до 25 КБ
   пробой мимо очереди (``core/probe_mark``): где обрыв есть.
2. **Подбор имени** — для каждой сети с обрывом в песочнице
   (``core/nfqws_sandbox``: второй nfqws2 на своей очереди, обход сети не
   трогается) перебираются приёмы :data:`TEMPLATES` с именами
   :data:`NAMES`; хватает первого, открывшего адрес 3 раза из 3.
   Сначала пробуется то, что уже помогло соседней сети.
3. **Итог** — ``<config_dir>/freeze.json``. Найденное идёт в подбор
   стратегий первым (:func:`candidates`, ``strategy_scanner``), а
   «Применить для сети» (:func:`apply_network`) ставит приём профилем на
   IP-список сети по ASN (RIPEstat, ``ipset_manager.load_by_asn``) через
   «Применить с проверкой».

Песочница обязательна: гасить обход всей сети на 15 минут подбора ради
пробы нельзя.

Чистые функции (:func:`networks`, :func:`variants`, :func:`candidates`,
:func:`network_profile`) отделены от прогона.
"""

from __future__ import annotations

import json
import os
import threading
import time

from core.log_buffer import log

SOURCE = "freeze"

# Имена для фейка — сайты, которые провайдеры обычно не трогают. Первыми —
# те, что снимали обрыв чаще (замеры z2k и dpi-detector, whitelist_sni).
NAMES = ("ya.ru", "300.ya.ru", "hcaptcha.com", "ad.adriver.ru", "vk.com",
         "gosuslugi.ru", "ozon.ru", "www.google.com")
# Приёмы, в которые подставляется имя (NAME). Первый снимает и замирание
# до ответа, второй — обрыв на объёме; третий — фейк с подменой SNI.
TEMPLATES = (
    ("--lua-desync=hostfakesplit:repeats=4:tcp_ts=-600000:tcp_md5:"
     "host=NAME",),
    ("--lua-desync=hostfakesplit:tcp_md5:tcp_ts_up:repeats=16:host=NAME",),
    ("--lua-desync=fake:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=NAME:"
     "tcp_md5:tcp_ts=-600000:repeats=16",),
)
# Фильтр профиля: обрыв лечится на ClientHello TLS.
FILTER = ("--filter-tcp=443", "--filter-l7=tls")
PAYLOAD = "--payload=tls_client_hello"

TOTAL_LIMIT = 900     # секунд на подбор имён всех сетей
# И на одну сеть: неудачный вариант стоит ~16 с (старт, тайм-аут
# загрузки, пауза, повтор) — в 400 с влезают все 24.
NET_LIMIT = 400
NEED_OK = 3           # засчитывается только «3 раза из 3»
URLS_PER_NET = 2      # адресов сети в пробе без обхода (первый живой)
RETRY_PAUSE = 3       # провайдер какое-то время помнит замёрзший адрес
STABILIZE_SEC = 1.0
# Тайм-аут одной загрузки при подборе: зависание на 16 КБ ждать 15 с
# (как в обычном тесте) — значит перебрать четыре имени вместо 24.
TRY_TIMEOUT = 6
# Песочница не поднялась столько раз подряд — дело не в варианте.
SANDBOX_FAILS = 3
# Сколько находок ставить первыми в подбор любого TLS-сайта: сеть сайта
# заранее неизвестна, а каждая лишняя — целая проба.
SCAN_FIRST_MAX = 3

PROFILE_PREFIX = "net16k-asn"
STRATEGY_PREFIX = "net16k-"

_lock = threading.Lock()
_stop = threading.Event()
_thread = None
_status = {"state": "idle"}


# ─────────────────────────── чистые функции ───────────────────────────

def networks(targets: list) -> list:
    """Цели ``tcp_targets.json`` → сети: по одной записи на ASN.

    Только HTTPS (приёмы — на ClientHello TLS); порядок — как в файле.
    Returns:
        [{"asn", "provider", "urls": [...]}]
    """
    out, by_asn = [], {}
    for t in targets or []:
        if not isinstance(t, dict):
            continue
        asn = str(t.get("asn") or "").strip()
        url = str(t.get("url") or "").strip()
        if not asn.isdigit() or not url.startswith("https://"):
            continue
        net = by_asn.get(asn)
        if net is None:
            net = {"asn": asn, "provider": str(t.get("provider") or ""),
                   "urls": []}
            by_asn[asn] = net
            out.append(net)
        elif t.get("provider") and t["provider"] not in net["provider"]:
            net["provider"] += " / " + t["provider"]
        net["urls"].append(url)
    return out


def variants(known_functions=None) -> list:
    """Шаги для перебора: сначала все имена с первым приёмом, потом
    остальные (сети различаются прежде всего именем). Приём с функцией,
    которой на устройстве нет, пропускается."""
    out = []
    for template in TEMPLATES:
        fn = template[0][len("--lua-desync="):].split(":", 1)[0]
        if known_functions is not None and fn not in known_functions:
            continue
        for name in NAMES:
            out.append({"name": name,
                        "steps": [s.replace("NAME", name) for s in template]})
    return out


def _title(steps: list, name: str) -> str:
    fn = steps[0][len("--lua-desync="):].split(":", 1)[0] if steps else "?"
    return "%s с именем %s" % (fn, name)


def candidates(state: dict) -> list:
    """Находки пробы → кандидаты подбора (``custom_candidates`` формат).

    Одинаковые шаги из разных сетей — один кандидат; первым — тот, что
    помог большему числу сетей.
    """
    from core.custom_candidates import sid
    merged = {}
    for net in (state or {}).get("nets") or []:
        found = net.get("found") or {}
        steps = found.get("steps")
        if not steps:
            continue
        key = tuple(steps)
        item = merged.setdefault(key, {
            "id": sid(list(steps)), "args": list(steps),
            "name": "Обрыв 16 КБ: " + _title(steps, found.get("name", "")),
            "nets": []})
        item["nets"].append("AS%s %s" % (net.get("asn"),
                                          net.get("provider") or ""))
    out = sorted(merged.values(), key=lambda c: -len(c["nets"]))
    for c in out:
        c["description"] = "проба обрыва 16 КБ: помогло в " + ", ".join(
            n.strip() for n in c.pop("nets"))
    return out


def network_profile(net: dict, ipset_name: str) -> dict:
    """Профиль стратегии «приём сети только для её адресов»."""
    steps = list((net.get("found") or {}).get("steps") or [])
    args = list(FILTER) + ["--ipset=lists/%s.txt" % ipset_name, PAYLOAD] \
        + steps
    return {"id": PROFILE_PREFIX + str(net.get("asn")),
            "name": "Обрыв 16 КБ: AS%s %s" % (net.get("asn"),
                                              net.get("provider") or ""),
            "args": " ".join(args), "enabled": True}


def with_profile(base: dict, profile: dict, scope: dict = None) -> dict:
    """Стратегия = профиль сети ПЕРВЫМ + профили базы (nfqws2 берёт
    первый подошедший, а профиль сети уже прочих: только её адреса).

    Поля базы сохраняются. Копия — уже не встроенная, и сборщик не
    ограничит её «голые приёмы» сам (``_autowrap_scope``) — поэтому они
    ограничиваются здесь, по ``scope`` базы. База, уже собранная здесь,
    правится на месте.
    """
    from core.strategy_builder import autowrap_bare_trick
    base = {k: v for k, v in dict(base or {}).items()
            if k not in ("is_builtin", "_filepath")}
    base_id = str(base.get("id") or "")
    profiles = []
    for p in base.get("profiles") or []:
        if not isinstance(p, dict) or p.get("id") == profile["id"]:
            continue
        p = dict(p)
        if scope and isinstance(p.get("args"), str):
            p["args"] = " ".join(autowrap_bare_trick(p["args"].split(),
                                                     **scope))
        profiles.append(p)
    out = dict(base)
    if not base_id.startswith(STRATEGY_PREFIX):
        out["id"] = STRATEGY_PREFIX + base_id
        out["name"] = "%s + обрыв 16 КБ" % (base.get("name") or base_id)
        out["description"] = ("профили сетей с обрывом 16 КБ поверх «%s»"
                              % (base.get("name") or base_id))
    out["profiles"] = [profile] + profiles
    return out


# ─────────────────────────────── файл ───────────────────────────────

def _path() -> str:
    from core.config_manager import get_config_manager
    return os.path.join(get_config_manager().config_dir, "freeze.json")


def load() -> dict:
    """Итог прошлой пробы ({} — не было)."""
    try:
        with open(_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(state: dict) -> None:
    from core.safe_io import atomic_write_json
    keep = ("state", "started", "finished", "nets", "error")
    try:
        atomic_write_json(_path(), {k: state[k] for k in keep if k in state})
    except (OSError, TypeError, ValueError) as e:
        log.warning("Итог пробы не сохранён: %s" % e, source=SOURCE)


def status() -> dict:
    """Ход пробы или итог прошлой: в памяти — этого процесса (переживёт
    и несохранённый файл), иначе с диска."""
    with _lock:
        if _status.get("state", "idle") != "idle":
            return json.loads(json.dumps(_status))
    data = load()
    return data if data else {"state": "idle"}


def running() -> bool:
    with _lock:
        return _status.get("state") == "running"


# ─────────────────────────────── прогон ───────────────────────────────

def _probe(url: str, mark: int, timeout: int = 0) -> str:
    """ok / freeze / error одной загрузки до 25 КБ.

    «ok» — только когда пришло больше 20 КБ: короткий ответ (страница
    ошибки, редирект) об обрыве ничего не говорит.
    """
    from core import probe_mark
    from core.testers.tcp_test import (TCP_BLOCK_RANGE_MAX,
                                       check_tcp_16_20_single)
    try:
        with probe_mark.marking(mark):
            r = (check_tcp_16_20_single(url, timeout) if timeout
                 else check_tcp_16_20_single(url))
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Проба %s: %s" % (url, e), source=SOURCE)
        return "error"
    if r.error == "TCP_16_20":
        return "freeze"
    got = int((r.raw_data or {}).get("bytes_received") or 0)
    return "ok" if r.status == "success" and got > TCP_BLOCK_RANGE_MAX \
        else "error"


def _preflight() -> dict:
    """Можно ли: песочница и замер «без обхода», не гася движок сети."""
    from core import nfqws_sandbox, probe_mark
    from core.nfqws_manager import get_nfqws_manager
    avail = nfqws_sandbox.available()
    if not avail["ok"]:
        return {"ok": False, "error": "нужна песочница подбора, а её нет: "
                                      "%s" % avail["reason"]}
    baseline = 0
    if get_nfqws_manager().is_running():
        mode = probe_mark.baseline_mode()
        if not mode["marked"]:
            return {"ok": False, "error": "замер без обхода невозможен, не "
                                          "останавливая обход сети: %s"
                                          % mode["reason"]}
        baseline = mode["mark"]
    return {"ok": True, "baseline_mark": baseline,
            "sandbox_mark": nfqws_sandbox.mark(),
            "queue": nfqws_sandbox.queue_num()}


def start() -> dict:
    """Запустить пробу фоном. Ответ — сразу."""
    global _thread
    from core import nfqws_control
    from core.testers.tcp_test import load_tcp_targets
    with _lock:
        if _status.get("state") == "running":
            return {"ok": False, "error": "проба уже идёт"}
    busy = nfqws_control.busy()
    if busy:
        return {"ok": False, "error": "движок занят: %s"
                % (busy.get("reason") or busy.get("who"))}
    pre = _preflight()
    if not pre["ok"]:
        return pre
    nets = networks(load_tcp_targets())
    if not nets:
        return {"ok": False, "error": "нет списка сетей "
                                      "(data/tcp_targets.json)"}
    with _lock:
        if _status.get("state") == "running":
            return {"ok": False, "error": "проба уже идёт"}
        _stop.clear()
        _status.clear()
        _status.update({"state": "running", "phase": "baseline",
                        "started": int(time.time()), "done": 0,
                        "total": len(nets), "current": "",
                        "nets": [dict(n, verdict="", found=None,
                                      tried=0, url="")
                                 for n in nets]})
        _thread = threading.Thread(target=_run, args=(pre,),
                                   name="freeze-probe", daemon=True)
        _thread.start()
    log.info("Проба «обрыв на 16 КБ»: %d сетей" % len(nets), source=SOURCE)
    return {"ok": True}


def stop() -> dict:
    _stop.set()
    return {"ok": True}


def _set(**fields) -> None:
    with _lock:
        _status.update(fields)


def _run(pre: dict) -> None:
    from core.nfqws_session import SessionBusy, get_nfqws_session
    from core.nfqws_session import OWNER_FREEZE
    try:
        with get_nfqws_session().acquire(
                owner=OWNER_FREEZE, timeout=0,
                reason="проба обрыва 16 КБ по сетям хостингов"):
            _run_locked(pre)
    except SessionBusy as busy:
        _set(state="error", error="движок занят: %s" % busy)
    except Exception as e:                      # noqa: BLE001 — граница
        log.error("Проба обрыва упала: %s" % e, source=SOURCE)
        _set(state="error", error="%s: %s" % (type(e).__name__, e))
    finally:
        # Сначала файл, потом конец прогона: иначе опрос между ними
        # увидел бы «не идёт» и прочитал прошлый итог с диска.
        with _lock:
            final = json.loads(json.dumps(_status))
        if final.get("state") == "running":
            final["state"] = "done"
        final["finished"] = int(time.time())
        final["current"] = ""
        _save(final)
        with _lock:
            _status.update(state=final["state"], finished=final["finished"],
                           current="")


def _baseline(nets: list, mark: int) -> None:
    for net in nets:
        if _stop.is_set():
            return
        _set(current="AS%s %s" % (net["asn"], net["provider"]))
        verdict = "error"
        for url in net["urls"][:URLS_PER_NET]:
            verdict = _probe(url, mark)
            if verdict == "freeze":
                # Обрыв подтверждается вторым замером: одиночный мог
                # оказаться просто медленным сервером.
                verdict = _probe(url, mark)
                if verdict == "error":
                    verdict = "freeze"
            if verdict != "error":
                net["url"] = url
                break
        with _lock:
            net["verdict"] = verdict
            _status["done"] += 1


def _try(sandbox, steps: list, url: str, mark: int) -> int:
    """Сколько из :data:`NEED_OK` загрузок прошли с этими шагами."""
    if not sandbox.start(list(FILTER) + [PAYLOAD] + list(steps)):
        return -1
    try:
        time.sleep(STABILIZE_SEC)
        if not sandbox.is_running():
            return -1
        ok = 0
        for i in range(NEED_OK):
            v = _probe(url, mark, TRY_TIMEOUT)
            if v != "ok" and i == 0:
                time.sleep(RETRY_PAUSE)
                v = _probe(url, mark, TRY_TIMEOUT)
            if v != "ok":
                break
            ok += 1
        return ok
    finally:
        sandbox.stop()


def _run_locked(pre: dict) -> None:
    from core import lint_env, nfqws_sandbox
    from core.firewall import get_firewall_manager

    with _lock:
        nets = _status["nets"]
    _baseline(nets, pre["baseline_mark"])
    frozen = [n for n in nets if n["verdict"] == "freeze"]
    _set(phase="names", total=len(nets) + len(frozen))
    if not frozen or _stop.is_set():
        if _stop.is_set():
            _set(state="stopped")
        return

    fw = get_firewall_manager()
    if not fw.apply_sandbox_rules(pre["queue"], pre["sandbox_mark"]):
        _set(state="error", error="правила песочницы не встали")
        return
    sandbox = nfqws_sandbox.NFQWSSandbox(pre["queue"])
    all_variants = variants(lint_env.known_functions())
    started = time.monotonic()
    fails = 0
    try:
        for net in frozen:
            # Сначала то, что уже помогло другой сети: часто подходит.
            helped = [n["found"] for n in nets if n.get("found")]
            order = helped + [v for v in all_variants
                              if v["steps"] not in
                              [h["steps"] for h in helped]]
            net_started = time.monotonic()
            for v in order:
                if _stop.is_set():
                    _set(state="stopped")
                    return
                if time.monotonic() - started > TOTAL_LIMIT:
                    _set(state="time")
                    return
                if time.monotonic() - net_started > NET_LIMIT:
                    with _lock:
                        net["gave_up"] = True
                    break
                _set(current="AS%s %s: %s" % (net["asn"], net["provider"],
                                               _title(v["steps"], v["name"])))
                ok = _try(sandbox, v["steps"], net["url"],
                          pre["sandbox_mark"])
                if ok == -1:
                    # Не вариант «не помог», а nfqws2 песочницы не встал;
                    # подряд — значит не встанет ни с каким.
                    fails += 1
                    if fails >= SANDBOX_FAILS:
                        _set(state="error", error="nfqws2 в песочнице не "
                             "запускается — подробности в журнале "
                             "(источник nfqws-sandbox)")
                        return
                    continue
                fails = 0
                with _lock:
                    net["tried"] += 1
                if ok == NEED_OK:
                    with _lock:
                        net["found"] = {"name": v["name"],
                                        "steps": list(v["steps"])}
                    log.info("AS%s %s: обрыв снимает %s" % (
                        net["asn"], net["provider"],
                        _title(v["steps"], v["name"])), source=SOURCE)
                    break
            with _lock:
                _status["done"] += 1
    finally:
        try:
            sandbox.stop()
        finally:
            fw.remove_sandbox_rules()


# ─────────────────────────── применить для сети ───────────────────────────

def apply_network(asn: str, timeout: int = 0) -> dict:
    """Приём сети → профиль на её IP-список (по ASN) → «Применить с
    проверкой». Текущая стратегия сохраняется под профилем сети."""
    from core import safe_apply
    from core.config_manager import get_config_manager
    from core.ipset_manager import get_ipset_manager
    from core.strategy_builder import get_strategy_manager

    from core import nfqws_control

    asn = str(asn or "").strip().upper()
    asn = asn[2:] if asn.startswith("AS") else asn
    if running():
        return {"ok": False, "error": "проба ещё идёт — дождитесь итога"}
    net = next((n for n in load().get("nets") or []
                if str(n.get("asn")) == asn and n.get("found")), None)
    if net is None:
        return {"ok": False, "error": "для AS%s проба ничего не нашла" % asn}
    sm = get_strategy_manager()
    current = get_config_manager().get("strategy", "current_id",
                                       default="") or ""
    base = sm.get_strategy(current) if current else None
    if not base:
        # Стратегия из одного профиля сети сняла бы обход всего прочего.
        return {"ok": False, "error": "сначала выберите стратегию: профиль "
                                      "сети ставится поверх текущей"}
    # Занято — до записи файлов: иначе список и стратегия остались бы,
    # а применение — нет.
    if safe_apply.active():
        return {"ok": False, "error": "идёт проверка другой стратегии — "
                                      "подтвердите или откатите её"}
    busy = nfqws_control.busy()
    if busy:
        return {"ok": False, "error": "движок занят: %s"
                % (busy.get("reason") or busy.get("who"))}
    prefixes = get_ipset_manager().load_by_asn(asn)
    if not prefixes:
        return {"ok": False, "error": "не удалось получить адреса AS%s у "
                                      "RIPEstat" % asn}
    ipset_name = "asn%s" % asn
    if not get_ipset_manager().save_ipset(ipset_name, prefixes):
        return {"ok": False, "error": "IP-список %s не записан" % ipset_name}
    saved = sm.save_user_strategy(with_profile(
        base, network_profile(net, ipset_name), sm._autowrap_scope(base)))
    if not saved:
        return {"ok": False, "error": "стратегия не сохранена"}
    kwargs = {"timeout": timeout} if timeout else {}
    res = safe_apply.start(saved["id"], **kwargs)
    res.update({"strategy_id": saved["id"], "ipset": ipset_name,
                "prefixes": len(prefixes)})
    return res
