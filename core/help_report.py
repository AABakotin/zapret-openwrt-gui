# core/help_report.py
"""
«Отчёт для помощи»: текст для вопроса в чате или issue одной кнопкой.

## Зачем

На вопрос «не работает обход» первым делом спрашивают одно и то же:
версии, платформа, запущен ли nfqws2, какая стратегия, какие списки,
что в журнале. Человек отвечает по частям, скриншотами, и половину
забывает. Здесь всё это собирается в один текст (приём nfqws2-ui).

## Чего в отчёте нет

* паролей, токенов, ключей — свободный текст (аргументы запуска, журнал)
  проходит ``core.mcp.redact.redact_text(force=True)``, как журнал MCP,
  а адреса в нём укорачиваются до хоста (``shorten_url``): в пути
  подписки бывает ключ. Собственные строки отчёта («- имя: значение»)
  через чистку пар «ключ: значение» не идут — иначе список с именем
  ``token`` терял бы счётчик;
* внешнего (публичного) адреса — глобальные IP маскируются всегда;
* содержимого списков — только имена и число записей;
* имён сайтов — по умолчанию тоже маскируются (``<домен-1>``), галочка
  «показать сайты» это выключает: иногда помогающему нужно знать, какой
  сайт не открывается.

Раздел «Версии» не маскируется: в нём нет ни сайтов, ни адресов, а
четырёхчастная версия (``1.12.4.1``) выглядит для маски как IP.

Маска — та же, что у черновиков issue (``core.mcp.issues.mask_text``).

## Ошибка — это не «нет»

Раздел, который не удалось собрать, так и подписан. «Конфликтов нет»
или «nfqws2 остановлен», выведенные из упавшей проверки, отправили бы
помогающего искать не там.

Отчёт ничего никуда не отправляет — его копирует человек.
"""

from __future__ import annotations

import re
import time

# Сколько строк журнала уровня WARNING+ класть в отчёт.
LOG_LINES = 30

_URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)


class _Failed(Exception):
    """Часть раздела не собралась — показать это, а не пустоту."""


def _section(title: str, fn) -> str:
    try:
        rows = [r for r in fn() if r]
    except Exception as e:                          # noqa: BLE001 — граница
        rows = ["- не удалось собрать: %s: %s" % (type(e).__name__,
                                                  str(e)[:120])]
    if not rows:
        return ""
    return "### %s\n%s\n" % (title, "\n".join(rows))


def _free_text(text: str) -> str:
    """Чистка свободного текста: секреты по маркерам, адреса — до хоста."""
    from core.mcp.redact import redact_text, shorten_url
    text = _URL_RE.sub(lambda m: shorten_url(m.group(0), force=True), text)
    return redact_text(text, force=True)


def _versions() -> list:
    from core.version import GUI_VERSION
    from core.mcp import issues
    from core.zapret_installer import get_zapret_installer
    rows = ["- zapret-gui: %s" % GUI_VERSION]
    env = issues._environment()
    rows.append("- платформа: %s, %s, ядро %s, python %s" % (
        env.get("platform", "?"), env.get("arch", "?"),
        env.get("kernel", "?"), env.get("python", "?")))
    zapret = get_zapret_installer().get_installed_version() or {}
    rows.append("- zapret2: %s" % (zapret.get("version") or "не установлен"))
    # Остальные движки — из кеша проверки обновлений (в сеть не ходим).
    # GUI и zapret2 оттуда не берём: выше они свежие, а кеш мог отстать.
    for e in issues._engines():
        if str(e.get("name", "")).lower() in ("gui", "zapret2", "zapret"):
            continue
        rows.append("- %s: %s" % (e.get("name", "?"), e.get("current", "?")))
    return rows


def _nfqws() -> list:
    from core.config_manager import get_config_manager
    from core.firewall import get_firewall_manager
    from core.nfqws_manager import get_nfqws_manager
    cfg = get_config_manager()
    st = get_nfqws_manager().get_status()
    rows = ["- nfqws2: %s%s%s" % (
        "работает" if st.get("running") else "остановлен",
        ", %s" % st["uptime_human"] if st.get("uptime_human") else "",
        " (поднят автозапуском)" if st.get("external") else "")]
    if st.get("exit_code") not in (None, 0):
        rows.append("- код выхода: %s" % st.get("exit_code"))
    rows.append("- стратегия: %s (%s)" % (
        cfg.get("strategy", "current_name") or "не выбрана",
        cfg.get("strategy", "current_id") or "—"))
    try:
        fw = get_firewall_manager().get_status()
        rows.append("- firewall: %s, правила %s" % (
            fw.get("type") or "?",
            "стоят (%s)" % fw.get("rules_count", 0) if fw.get("applied")
            else "не стоят"))
    except Exception as e:                          # noqa: BLE001 — граница
        rows.append("- firewall: не удалось узнать (%s)" % type(e).__name__)
    args = st.get("last_args") or []
    if args:
        rows.append("- аргументы последнего запуска:\n```\n%s\n```"
                    % _free_text(" ".join(str(a) for a in args)))
    return rows


def _lists() -> list:
    from core.hostlist_manager import get_hostlist_manager
    from core import list_lint
    hm = get_hostlist_manager()
    try:
        usage = list_lint.strategy_list_usage(list_lint._current_argv())
        unknown = ""
    except Exception as e:                          # noqa: BLE001 — граница
        usage, unknown = {}, "как читает стратегия — неизвестно (%s)" % (
            type(e).__name__)
    stats = hm.get_stats()
    rows = []
    for name in hm.list_names():
        st = stats.get(name) or {}
        kind = unknown or {"bypass": "обход", "exclude": "исключения"}.get(
            usage.get(name, ""), "не подключён")
        rows.append("- %s: %s записей, %s" % (name, st.get("count", "?"),
                                              kind))
    return rows


def _conflicts() -> list:
    from core import diagnostics
    rows = []
    for w in diagnostics.check_known_conflicts().get("warnings") or []:
        rows.append("- %s: %s" % (w.get("title", ""), w.get("detail", "")))
    for c in diagnostics.check_nfqws_conflicts().get("conflicts") or []:
        rows.append("- посторонний %s (pid %s)" % (c.get("name"), c.get("pid")))
    return rows or ["- нет"]


def _tunnels() -> list:
    from core import tunnels_overview
    rows = []
    for e in tunnels_overview.overview(logs=False).get("engines") or []:
        if not e.get("installed"):
            continue
        rows.append("- %s %s: %s, экземпляров %d/%d" % (
            e.get("title", e.get("engine")), e.get("version", ""),
            "работает" if e.get("running") else "не работает",
            e.get("running_count", 0), e.get("instances_count", 0)))
    return rows


def _healthcheck() -> list:
    from core.healthcheck import get_healthcheck
    st = get_healthcheck().get_status()
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
    entries = get_log_buffer().get_filtered(level="WARNING", n=LOG_LINES)
    if not entries:
        return []
    lines = ["%s %s [%s] %s" % (e.get("date", ""), e.get("time", ""),
                                e.get("level", ""),
                                "%s: %s" % (e["source"], e.get("message", ""))
                                if e.get("source") else e.get("message", ""))
             for e in entries]
    return ["```\n%s\n```" % _free_text("\n".join(lines))]


def collect() -> dict:
    """Собрать разделы один раз: {"versions": текст, "body": текст}.

    Маскировка — отдельно (:func:`render`), чтобы галочка «показать сайты»
    не пересобирала отчёт заново.
    """
    head = "## Отчёт zapret-gui · %s\n" % time.strftime("%Y-%m-%d %H:%M")
    versions = _section("Версии", _versions)
    body = "\n".join(p for p in (
        _section("Обход DPI", _nfqws),
        _section("Списки", _lists),
        _section("Конфликты", _conflicts),
        _section("Туннели", _tunnels),
        _section("Мониторинг", _healthcheck),
        _section("Журнал: предупреждения и ошибки", _log_tail),
    ) if p)
    return {"versions": head + versions, "body": body}


def render(parts: dict, show_sites: bool = False) -> dict:
    """Отчёт из собранных разделов с нужной маской.

    Returns:
        {"text": markdown, "masked": сколько значений замаскировано}
    """
    from core.mcp.issues import mask_text
    body, masked = mask_text(parts.get("body", ""), sites=not show_sites)
    return {"text": parts.get("versions", "") + "\n" + body,
            "masked": masked}


def build(show_sites: bool = False) -> dict:
    """Собрать отчёт. См. :func:`collect` и :func:`render`."""
    return render(collect(), show_sites=show_sites)


def build_both() -> dict:
    """Оба варианта из одного сбора: {"masked": {...}, "sites": {...}}.

    Для UI: переключение галочки не ходит на роутер ещё раз и не может
    получить ответ «не того» запроса.
    """
    parts = collect()
    return {"masked": render(parts, show_sites=False),
            "sites": render(parts, show_sites=True)}
