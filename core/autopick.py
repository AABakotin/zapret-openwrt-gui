# core/autopick.py
"""
Автоподбор стратегии по мониторингу: сайт перестал открываться — найти,
чем его открыть.

## Как работает

Мониторинг (``core/healthcheck.py``) замечает переход «открывался → не
открывается» (``consecutive_failures`` проверок подряд) и зовёт
:func:`trigger`. Дальше в фоне:

1. **Подбор** — тот же сканер, что на странице «Подбор стратегий»
   (``core/strategy_scanner``), по первому хосту сайта, быстрый режим,
   до :data:`STOP_AFTER` рабочих находок с перепроверкой. Кандидаты из
   памяти подбора (``core/strategy_memory``: «что уже помогало этому
   сайту в этой сети») сканер ставит первыми сам.
2. **Только в песочнице** (``core/nfqws_sandbox``): кандидаты гоняются
   во втором nfqws2, обход остальной сети не трогается. Без песочницы
   автоподбор не запускается — останавливать обход всем ради одного
   сайта без спроса нельзя.
3. **Итог** по режиму ``healthcheck.autopick.mode``:

   * ``suggest`` (по умолчанию при включении) — лучшая находка
     сохраняется своей стратегией и предлагается: уведомление и карточка
     на странице «Стратегии» с кнопкой «Применить с проверкой»;
   * ``apply`` — применяется сама через «Применить с проверкой» в
     режиме без человека (``safe_apply.start(auto_target=…)``): если
     сайт открылся и ничего из открывавшегося не перестало — остаётся,
     иначе откат сразу.

Найденная стратегия заменяет текущую целиком (как кнопка «Применить» в
подборе) — поэтому замер «после» смотрит на все сайты мониторинга.

## Пределы

Один сайт — не чаще раза в ``min_interval_h`` часов (подбор нагружает
роутер и сеть), одновременно — один подбор; занят движок (идёт подбор
вручную, эксперимент, проверка стратегии) — пропуск.

Состояние — ``<config_dir>/autopick.json``: последний прогон по сайту и
текущее предложение.
"""

from __future__ import annotations

import json
import os
import threading
import time

from core.log_buffer import log

MODES = ("off", "suggest", "apply")
STOP_AFTER = 3
SCAN_MODE = "quick"
# Предел ожидания подбора, сек (быстрый режим — десятки стратегий).
SCAN_TIMEOUT = 1800
DEFAULT_INTERVAL_H = 6

SOURCE = "autopick"

_lock = threading.Lock()
_running = {"key": ""}


def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def settings() -> dict:
    sec = _cfg().get("healthcheck", "autopick", default={}) or {}
    mode = str(sec.get("mode") or "off").strip().lower()
    try:
        hours = float(sec.get("min_interval_h", DEFAULT_INTERVAL_H))
    except (TypeError, ValueError):
        hours = DEFAULT_INTERVAL_H
    return {"mode": mode if mode in MODES else "off",
            "min_interval_h": max(0.5, hours)}


def _path() -> str:
    return os.path.join(_cfg().config_dir, "autopick.json")


def _read() -> dict:
    try:
        with open(_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data: dict) -> None:
    from core.safe_io import atomic_write_json
    atomic_write_json(_path(), data)


def _set_run(key: str, **fields) -> dict:
    with _lock:
        data = _read()
        runs = data.setdefault("runs", {})
        run = dict(runs.get(key) or {})
        run.update(fields)
        runs[key] = run
        _write(data)
        return run


def status() -> dict:
    data = _read()
    return {"ok": True, "settings": settings(),
            "running": _running["key"] or None,
            "suggestion": data.get("suggestion") or None,
            "runs": data.get("runs") or {}}


def _notify(text: str) -> None:
    from core import notify
    notify.event("autopick", text)


# ─────────────────────────── решение «запускать ли» ────────────────────

def should_run(key: str, now: float, last_ts: float, mode: str,
               interval_h: float, busy: str = "") -> str:
    """Чистая функция: причина НЕ запускать ("" — запускать)."""
    if mode not in ("suggest", "apply"):
        return "автоподбор выключен"
    if busy:
        return "занято: %s" % busy
    if last_ts and now - last_ts < interval_h * 3600:
        return "подбор для %s уже был недавно" % key
    return ""


def _busy() -> str:
    if _running["key"]:
        return "идёт автоподбор для %s" % _running["key"]
    try:
        from core import safe_apply
        if safe_apply.active():
            return "идёт проверка стратегии"
    except Exception:                               # noqa: BLE001
        pass
    try:
        from core import nfqws_control
        b = nfqws_control.busy() or {}
        if b:
            return b.get("reason") or b.get("who") or "движок занят"
    except Exception:                               # noqa: BLE001
        pass
    return ""


def trigger(display: str, hosts) -> dict:
    """Сайт ``display`` перестал открываться: подобрать стратегию в фоне.

    Безопасно звать из потока мониторинга: решает быстро, работу уносит
    в свой поток, ничего не бросает.
    """
    try:
        st = settings()
        if st["mode"] == "off":
            return {"ok": False, "reason": "автоподбор выключен"}
        host = next((h for h in (hosts or []) if h), "")
        if not host:
            return {"ok": False, "reason": "нет хоста"}
        last = float(((_read().get("runs") or {}).get(display) or {})
                     .get("ts") or 0)
        why = should_run(display, time.time(), last, st["mode"],
                         st["min_interval_h"], _busy())
        if why:
            if st["mode"] != "off":
                log.info("автоподбор для %s пропущен: %s" % (display, why),
                         source=SOURCE)
            return {"ok": False, "reason": why}
        from core import nfqws_sandbox
        avail = nfqws_sandbox.available()
        if not avail.get("ok"):
            reason = "нет песочницы (%s)" % avail.get("reason", "")
            log.warning("автоподбор для %s не запущен: %s — подбор занял "
                        "бы основной обход" % (display, reason),
                        source=SOURCE)
            _set_run(display, ts=time.time(), result="skipped",
                     reason=reason)
            return {"ok": False, "reason": reason}
        with _lock:
            if _running["key"]:
                return {"ok": False, "reason": "уже идёт"}
            _running["key"] = display
        threading.Thread(target=_run, args=(display, host, st["mode"]),
                         name="autopick", daemon=True).start()
        return {"ok": True}
    except Exception as e:                          # noqa: BLE001 — граница
        log.warning("автоподбор: %s" % e, source=SOURCE)
        return {"ok": False, "reason": str(e)}


# ─────────────────────────── прогон ────────────────────────────

def best(working: list) -> dict | None:
    """Чистая функция: лучшая находка (по score, потом по задержке)."""
    if not working:
        return None
    return sorted(working, key=lambda r: (-float(r.get("score") or 0),
                                          float(r.get("latency_ms") or 0)))[0]


def _scan(host: str) -> list:
    from core.strategy_scanner import (STATUS_RUNNING,
                                       get_strategy_scanner)
    sc = get_strategy_scanner()
    if not sc.start(target=host, protocol="tcp", mode=SCAN_MODE,
                    stop_after=STOP_AFTER, confirm=True):
        raise RuntimeError("сканер занят")
    deadline = time.time() + SCAN_TIMEOUT
    while sc.get_status().get("status") == STATUS_RUNNING:
        if time.time() > deadline:
            sc.stop()
            raise RuntimeError("подбор не уложился в %d мин"
                               % (SCAN_TIMEOUT // 60))
        time.sleep(3)
    return sc.get_working_strategies()


def _run(display: str, host: str, mode: str) -> None:
    started = time.time()
    _set_run(display, ts=started, host=host, result="running", reason="")
    log.info("автоподбор: %s не открывается — подбираю стратегию для %s"
             % (display, host), source=SOURCE)
    try:
        working = _scan(host)
        top = best(working)
        if not top:
            _set_run(display, result="nothing",
                     reason="рабочих стратегий не нашлось")
            _notify("🔎 Автоподбор для %s: рабочих стратегий не нашлось"
                    % display)
            return
        from core.strategy_scanner import get_strategy_scanner
        saved = get_strategy_scanner().save_working_by_id(
            top.get("strategy_id"))
        if not saved:
            raise RuntimeError("находку не удалось сохранить")
        suggestion = {"ts": time.time(), "site": display, "host": host,
                      "strategy_id": saved["id"],
                      "strategy_name": saved.get("name", ""),
                      "found": len(working)}
        if mode == "apply":
            from core import safe_apply
            res = safe_apply.start(saved["id"], auto_target=display)
            if not res.get("ok"):
                raise RuntimeError(res.get("error") or "не применилась")
            _set_run(display, result="applying",
                     strategy_id=saved["id"],
                     strategy_name=saved.get("name", ""))
            _notify("🔎 Автоподбор для %s: применяю «%s» с проверкой"
                    % (display, saved.get("name", "")))
            return
        with _lock:
            data = _read()
            data["suggestion"] = suggestion
            _write(data)
        _set_run(display, result="suggested", strategy_id=saved["id"],
                 strategy_name=saved.get("name", ""))
        _notify("🔎 Для %s нашлась стратегия «%s». Применить: «Стратегии» "
                "→ «Применить с проверкой»." % (display,
                                               saved.get("name", "")))
    except Exception as e:                          # noqa: BLE001 — граница
        _set_run(display, result="error", reason=str(e))
        log.warning("автоподбор для %s: %s" % (display, e), source=SOURCE)
    finally:
        _running["key"] = ""


def dismiss() -> dict:
    """Убрать текущее предложение."""
    with _lock:
        data = _read()
        data.pop("suggestion", None)
        _write(data)
    return {"ok": True}


def apply_suggestion() -> dict:
    """«Применить с проверкой» для текущего предложения."""
    sug = _read().get("suggestion") or {}
    if not sug.get("strategy_id"):
        return {"ok": False, "error": "предложения нет"}
    from core import safe_apply
    res = safe_apply.start(sug["strategy_id"])
    if res.get("ok"):
        dismiss()
    return res
