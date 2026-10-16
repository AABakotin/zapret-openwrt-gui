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
   сайта без спроса нельзя. Окончательно это решает сам сканер
   (``require_isolation=True``): его проверка строже (ещё и baseline с
   меткой мимо очереди), и между нашей проверкой и его стартом
   условия могли измениться.
3. **Итог** по режиму ``healthcheck.autopick.mode``:

   * ``suggest`` (по умолчанию при включении) — лучшая находка
     сохраняется своей стратегией и предлагается: уведомление и карточка
     на странице «Стратегии» с кнопкой «Применить с проверкой»;
   * ``apply`` — применяется сама через «Применить с проверкой» в
     режиме без человека (``safe_apply.start(auto_target=…)``): если
     сайт открылся и ничего из открывавшегося не перестало — остаётся,
     иначе откат сразу.

Найденная стратегия заменяет текущую целиком (как кнопка «Применить» в
подборе). Замер «после» видит только сайты мониторинга, поэтому сам
автоподбор применяет находку, лишь когда текущая стратегия — не больше
одного профиля (нечего потерять сверх видимого); иначе — предлагает.

Предложения хранятся по сайту: находка для второго сайта не стирает
первую.

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
# Сайты, чей подбор отложен из-за занятости (идёт другой подбор, проверка
# стратегии, сканер): мониторинг повторит запуск на следующей неудачной
# проверке, а не только на новом переходе «открывается → нет».
_pending = set()


class _Busy(RuntimeError):
    """Сканер занят: подбор не начался, повторить позже."""


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


def suggestions(data: dict | None = None) -> list:
    data = _read() if data is None else data
    items = list((data.get("suggestions") or {}).values())
    return sorted(items, key=lambda x: -float(x.get("ts") or 0))


def status() -> dict:
    data = _read()
    return {"ok": True, "settings": settings(),
            "running": _running["key"] or None,
            "suggestions": suggestions(data),
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


def pending(display: str) -> bool:
    """Отложен ли подбор для ``display`` из-за занятости."""
    return display in _pending


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
        busy = _busy()
        why = should_run(display, time.time(), last, st["mode"],
                         st["min_interval_h"], busy)
        if why and busy and why.startswith("занято"):
            _pending.add(display)
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
                _pending.add(display)
                return {"ok": False, "reason": "уже идёт"}
            _running["key"] = display
            _pending.discard(display)
        threading.Thread(target=_run, args=(display, host, st["mode"], last),
                         name="autopick", daemon=True).start()
        return {"ok": True}
    except Exception as e:                          # noqa: BLE001 — граница
        log.warning("автоподбор: %s" % e, source=SOURCE)
        return {"ok": False, "reason": str(e)}


# ─────────────────────────── прогон ────────────────────────────

def best(working: list) -> dict | None:
    """Чистая функция: лучшая находка — как у отчёта сканера: сначала
    перепроверенные, потом по score, потом по задержке."""
    if not working:
        return None
    return sorted(working, key=lambda r: (not r.get("confirmed"),
                                          -float(r.get("score") or 0),
                                          float(r.get("latency_ms") or 0)))[0]


def _scan(host: str) -> list:
    from core.strategy_scanner import (STATUS_COMPLETED, STATUS_RUNNING,
                                       get_strategy_scanner)
    sc = get_strategy_scanner()
    if not sc.start(target=host, protocol="tcp", mode=SCAN_MODE,
                    stop_after=STOP_AFTER, confirm=True,
                    require_isolation=True):
        raise _Busy(getattr(sc, "refusal", "") or "сканер занят")
    deadline = time.time() + SCAN_TIMEOUT
    while sc.get_status().get("status") == STATUS_RUNNING:
        if time.time() > deadline:
            sc.stop()
            raise RuntimeError("подбор не уложился в %d мин"
                               % (SCAN_TIMEOUT // 60))
        time.sleep(3)
    # Статус «готово» ставится до уборки и освобождения движка — ждём
    # сам поток, иначе применение наткнулось бы на «движок занят».
    thread = getattr(sc, "_thread", None)
    if thread is not None and thread.is_alive():
        thread.join(120)
    st = sc.get_status()
    if st.get("status") != STATUS_COMPLETED:
        raise RuntimeError("подбор не завершился: %s" % (
            st.get("error") or st.get("status") or "?"))
    return sc.get_working_strategies()


def _single_profile_now() -> bool:
    """Текущая стратегия — не больше одного включённого профиля."""
    sid = _cfg().get("strategy", "current_id")
    if not sid:
        return True
    from core.strategy_builder import get_strategy_manager
    s = get_strategy_manager().get_strategy(sid) or {}
    enabled = [p for p in s.get("profiles") or [] if p.get("enabled", True)]
    return len(enabled) <= 1


def _wait_safe_apply(display: str, name: str) -> None:
    """Дождаться итога автоприменения и записать его."""
    from core import safe_apply
    thread = safe_apply._thread
    if thread is not None:
        thread.join(SCAN_TIMEOUT)
    s = (safe_apply._read().get("session") or {})
    phase = s.get("phase") or "?"
    result = {"confirmed": "applied"}.get(phase, phase)
    _set_run(display, result=result, reason=s.get("reason") or "")
    if phase == "failed":
        _notify("⚠️ Автоподбор для %s: «%s» не применилась — %s"
                % (display, name, s.get("reason") or "?"))


def _run(display: str, host: str, mode: str, last: float = 0) -> None:
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
        name = saved.get("name", "")
        suggestion = {"ts": time.time(), "site": display, "host": host,
                      "strategy_id": saved["id"], "strategy_name": name,
                      "found": len(working)}
        note = ""
        if mode == "apply" and not _single_profile_now():
            note = (" Сама не применена: текущая стратегия из нескольких "
                    "профилей, замена могла бы сломать то, чего нет в "
                    "мониторинге.")
        elif mode == "apply":
            from core import safe_apply
            res = safe_apply.start(saved["id"], auto_target=display)
            if not res.get("ok"):
                raise RuntimeError(res.get("error") or "не применилась")
            _set_run(display, result="applying", strategy_id=saved["id"],
                     strategy_name=name)
            _notify("🔎 Автоподбор для %s: применяю «%s» с проверкой"
                    % (display, name))
            _wait_safe_apply(display, name)
            return
        with _lock:
            data = _read()
            data.setdefault("suggestions", {})[display] = suggestion
            _write(data)
        _set_run(display, result="suggested", strategy_id=saved["id"],
                 strategy_name=name, reason=note.strip())
        _notify("🔎 Для %s нашлась стратегия «%s». Применить: «Стратегии» "
                "→ «Применить с проверкой».%s" % (display, name, note))
    except _Busy as e:
        # Подбор не начался — интервал не тратится: время прошлого
        # прогона возвращается, мониторинг повторит запуск.
        _pending.add(display)
        _set_run(display, ts=last, result="deferred", reason=str(e))
        log.info("автоподбор для %s отложен: %s" % (display, e),
                 source=SOURCE)
    except Exception as e:                          # noqa: BLE001 — граница
        _set_run(display, result="error", reason=str(e))
        log.warning("автоподбор для %s: %s" % (display, e), source=SOURCE)
    finally:
        _running["key"] = ""


def dismiss(site: str) -> dict:
    """Убрать предложение для сайта."""
    with _lock:
        data = _read()
        (data.get("suggestions") or {}).pop(site, None)
        _write(data)
    return {"ok": True}


def apply_suggestion(site: str) -> dict:
    """«Применить с проверкой» для предложения по сайту."""
    sug = (_read().get("suggestions") or {}).get(site) or {}
    if not sug.get("strategy_id"):
        return {"ok": False, "error": "предложения нет"}
    from core import safe_apply
    res = safe_apply.start(sug["strategy_id"])
    if res.get("ok"):
        dismiss(site)
    return res
