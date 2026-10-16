# core/lint_env.py
"""
Окружение линтера стратегий: какие ``--lua-desync``-функции и blob'ы есть
на ЭТОМ устройстве.

Сам линтер (``core/strategy_lint.py``) — чистые функции без I/O и падать
на устройстве без zapret2 не должен, поэтому окружение собирается здесь и
передаётся ему аргументами. Пользуются MCP (``strategy_compose`` /
``strategy_validate``) и «своя стратегия» в подборе
(``core/custom_candidates.py``).
"""


def known_functions():
    """Имена ``--lua-desync`` этого устройства или ``None``.

    ``None`` (карту собрать не удалось) значит «правило не проверяем»:
    объявить неизвестной каждую функцию хуже, чем не проверить ни одной.
    """
    try:
        from core.lua_manager import get_lua_manager
        names = {item["name"] for item in get_lua_manager().desync_functions()}
    except Exception:                           # noqa: BLE001 — граница
        return None
    return names or None


def known_blobs():
    """``{имя: есть ли файл}`` — реестр блобов плюс переменные lua."""
    try:
        from core.blob_registry import list_blobs
        known = {item["name"]: bool(item.get("exists"))
                 for item in list_blobs()}
    except Exception:                           # noqa: BLE001 — граница
        return None
    try:
        from core.nfqws_manager import lua_named_patterns
        # tls_rnd, tls_youtube и прочие — это не файлы, а глобальные
        # переменные из init_vars.lua; движок подмешивает его сам.
        for name in lua_named_patterns():
            known.setdefault(name, True)
    except Exception:                           # noqa: BLE001 — граница
        pass
    return known or None
