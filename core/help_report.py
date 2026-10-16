# core/help_report.py
"""
«Отчёт для помощи»: текст для вопроса в чате или issue одной кнопкой.

## Зачем

На вопрос «не работает обход» первым делом спрашивают одно и то же:
версии, платформа, запущен ли nfqws2, какая стратегия, какие списки,
что в журнале. Человек отвечает по частям, скриншотами, и половину
забывает. Здесь всё это собирается в один текст (приём nfqws2-ui).

## Чего в отчёте нет

* паролей, токенов, ключей — весь текст проходит
  ``core.mcp.redact.redact_text(force=True)``, как журнал MCP;
* внешнего (публичного) адреса — глобальные IP маскируются всегда;
* содержимого списков — только имена и число записей;
* имён сайтов — по умолчанию тоже маскируются (``<домен-1>``), галочка
  «показать сайты» это выключает: иногда помогающему нужно знать, какой
  сайт не открывается.

Маскировка — та же, что у черновиков issue (``core/mcp/issues._Masker``):
одна метка на одно значение во всём отчёте, адреса апстримов и GitHub
не прячутся.

Отчёт ничего никуда не отправляет — его копирует человек.
"""

from __future__ import annotations

import time

# Сколько строк журнала уровня WARNING+ класть в отчёт.
LOG_LINES = 30


def _section(title: str, rows) -> str:
    rows = [r for r in rows if r]
    if not rows:
        return ""
    return "### %s\n%s\n" % (title, "\n".join(rows))


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:                               # noqa: BLE001 — граница
        return default


def _versions() -> list:
    from core.version import GUI_VERSION
    from core.mcp import issues
    rows = ["- zapret-gui: %s" % GUI_VERSION]
    env = _safe(issues._environment, {}) or {}
    if env:
        rows.append("- платформа: %s, %s, ядро %s, python %s" % (
            env.get("platform", "?"), env.get("arch", "?"),
            env.get("kernel", "?"), env.get("python", "?")))
    zapret = _safe(lambda: __import__(
        "core.zapret_installer", fromlist=["x"]).get_zapret_installer()
        .get_installed_version(), {}) or {}
    rows.append("- zapret2: %s" % (zapret.get("version") or "не установлен"))
    for e in _safe(issues._engines, []) or []:
        rows.append("- %s: %s" % (e.get("name", "?"), e.get("current", "?")))
    return rows


def _nfqws() -> list:
    from core.config_manager import get_config_manager
    from core.nfqws_manager import get_nfqws_manager
    cfg = get_config_manager()
    st = _safe(lambda: get_nfqws_manager().get_status(), {}) or {}
    rows = ["- nfqws2: %s%s%s" % (
        "работает" if st.get("running") else "остановлен",
        ", %s" % st["uptime_human"] if st.get("uptime_human") else "",
        " (поднят автозапуском)" if st.get("external") else "")]
    if st.get("exit_code") not in (None, 0):
        rows.append("- код выхода: %s" % st.get("exit_code"))
    rows.append("- стратегия: %s (%s)" % (
        cfg.get("strategy", "current_name") or "не выбрана",
        cfg.get("strategy", "current_id") or "—"))
    fw = _safe(lambda: __import__("core.firewall", fromlist=["x"])
               .get_firewall_manager().get_status(), {}) or {}
    if fw:
        rows.append("- firewall: %s, правила %s" % (
            fw.get("type") or "?",
            "стоят (%s)" % fw.get("rules_count", 0) if fw.get("applied")
            else "не стоят"))
    args = st.get("last_args") or []
    if args:
        rows.append("- аргументы последнего запуска:\n```\n%s\n```"
                    % " ".join(str(a) for a in args))
    return rows


def _lists() -> list:
    from core.hostlist_manager import get_hostlist_manager
    from core import list_lint
    hm = get_hostlist_manager()
    usage = _safe(lambda: list_lint.strategy_list_usage(
        list_lint._current_argv()), {}) or {}
    stats = _safe(hm.get_stats, {}) or {}
    rows = []
    for name in _safe(hm.list_names, []) or []:
        st = stats.get(name) or {}
        kind = {"bypass": "обход", "exclude": "исключения"}.get(
            usage.get(name, ""), "не подключён")
        rows.append("- %s: %s записей, %s" % (
            name, st.get("count", "?"), kind))
    return rows


def _conflicts() -> list:
    from core import diagnostics
    rows = []
    known = _safe(diagnostics.check_known_conflicts, {}) or {}
    for w in known.get("warnings") or []:
        rows.append("- %s: %s" % (w.get("title", ""), w.get("detail", "")))
    own = _safe(diagnostics.check_nfqws_conflicts, {}) or {}
    for c in own.get("conflicts") or []:
        rows.append("- посторонний %s (pid %s)" % (c.get("name"), c.get("pid")))
    return rows


def _tunnels() -> list:
    from core import tunnels_overview
    data = _safe(lambda: tunnels_overview.overview(logs=False), {}) or {}
    rows = []
    for e in data.get("engines") or []:
        if not e.get("installed"):
            continue
        rows.append("- %s %s: %s, экземпляров %d/%d" % (
            e.get("title", e.get("engine")), e.get("version", ""),
            "работает" if e.get("running") else "не работает",
            e.get("running_count", 0), e.get("instances_count", 0)))
    return rows


def _healthcheck() -> list:
    from core.healthcheck import get_healthcheck
    st = _safe(lambda: get_healthcheck().get_status(), {}) or {}
    if not st.get("enabled"):
        return ["- мониторинг выключен"]
    rows = ["- мониторинг: каждые %s мин" % st.get("interval_min")]
    summary = st.get("last_summary") or {}
    if summary:
        rows.append("  - последняя проверка: доступно %s из %s%s" % (
            summary.get("ok", "?"), summary.get("total", "?"),
            ", упало всё (нет связи?)" if summary.get("global_outage")
            else ""))
    for name, streak in sorted((st.get("fail_streak") or {}).items()):
        if streak:
            rows.append("  - %s: %s неудач подряд" % (name, streak))
    return rows


def _log_tail() -> list:
    from core.log_buffer import get_log_buffer
    entries = _safe(lambda: get_log_buffer().get_filtered(
        level="WARNING", n=LOG_LINES), []) or []
    if not entries:
        return []
    lines = ["%s %s [%s] %s" % (e.get("date", ""), e.get("time", ""),
                                e.get("level", ""),
                                "%s: %s" % (e["source"], e.get("message", ""))
                                if e.get("source") else e.get("message", ""))
             for e in entries]
    return ["```\n%s\n```" % "\n".join(lines)]


def build(show_sites: bool = False) -> dict:
    """Собрать отчёт.

    Args:
        show_sites: не маскировать имена сайтов (адреса — маскируются
            всегда).

    Returns:
        {"text": markdown, "masked": сколько значений замаскировано}
    """
    from core.mcp import issues
    from core.mcp.redact import redact_text

    parts = [
        "## Отчёт zapret-gui · %s" % time.strftime("%Y-%m-%d %H:%M"),
        _section("Версии", _safe(_versions, [])),
        _section("Обход DPI", _safe(_nfqws, [])),
        _section("Списки", _safe(_lists, [])),
        _section("Конфликты", _safe(_conflicts, []) or ["- нет"]),
        _section("Туннели", _safe(_tunnels, [])),
        _section("Мониторинг", _safe(_healthcheck, [])),
        _section("Журнал: предупреждения и ошибки", _safe(_log_tail, [])),
    ]
    text = "\n".join(p for p in parts if p)
    text = redact_text(text, force=True)
    masker = issues._Masker(enabled=True)
    if show_sites:
        # Только адреса: сайты нужны тому, кто помогает.
        text = issues._IPV4_RE.sub(lambda m: masker._ip(m.group(1)), text)
        text = issues._IPV6_RE.sub(lambda m: masker._ip(m.group(1)), text)
    else:
        text = masker(text)
    return {"text": text, "masked": masker.count}
