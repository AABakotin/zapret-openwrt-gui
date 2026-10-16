# core/scan_parallel.py
"""
Параллельный подбор: несколько кандидатов в одной песочнице разом.

## Зачем

Каталог — сотни стратегий, а сканер проверял их по одной: на каждую —
старт nfqws2, стабилизация, загрузка 64 КБ. Полный прогон шёл часами.
Приём nfqws2-ui: пачка до :data:`PAR_MAX` кандидатов поднимается в ОДНОМ
nfqws2 песочницы — каждый своим профилем, — и пробы идут параллельно.

## Как пакеты находят свой профиль

* Проба дорожки ``k`` открывает сокеты с исходными портами из своего
  диапазона (:func:`slot_ports`, ``probe_mark.marking(ports=…)``).
* Правила песочницы (``FirewallManager.apply_sandbox_rules(slots=…)``)
  по этому порту ставят пакету метку дорожки (:func:`slot_mark`, биты
  :data:`PAR_MASK`) — в обе стороны, после маршрутизации.
* Профиль кандидата начинается с ``--filter-mark=<метка>/<маска>``
  (nfqws2 1.0.5+): nfqws2 отдаёт пакет только профилю своей дорожки.

## Сколько дорожек

По памяти (:func:`slots_for_memory`): на Keenetic со 128 МБ 15 дорожек
разом уводили память в zram-swap, и роутер переставал отвечать. Считается
перед каждой пачкой: и по свободной памяти, и по объёму всей (128 МБ — 5,
256 МБ — 10, от 384 МБ — 15).

## Чему не верить

15 соединений к одному сайту разом иногда путают оборудование
провайдера, и параллельный итог расходится с проверкой по одной. Поэтому
каждая находка пачки сразу перепроверяется в одиночку, и в результаты
идёт одиночный замер.

Чистые функции; I/O — в сканере.
"""

from __future__ import annotations

import re

PAR_MAX = 15
# Биты метки дорожки. На Keenetic это биты политик NDMS — но метка
# ставится в POSTROUTING/PREROUTING, после выбора маршрута, и только
# соединениям песочницы.
PAR_MASK = 0x0F000000
# Исходные порты дорожек: вне эфемерного диапазона Linux (32768–60999
# по умолчанию) их занять некому; по 64 на дорожку.
PORT_BASE = 20000
PORTS_PER_SLOT = 64
# Меньше кандидатов — по одной, как раньше: выигрыша нет.
PAR_MIN = 12

SLOT_MB = 1.5          # память на дорожку: поток, TLS, буферы
RESERVE_MB = 15        # остаётся системе и прошивке
RAM_PER_SLOT_MB = 24   # и не больше дорожки на столько памяти всего

# Опции, которые nfqws2 читает до первого профиля (глобальные).
_GLOBAL_PREFIXES = ("--blob=", "--lua-init=")
_MEMINFO_RE = re.compile(r"^(MemTotal|MemAvailable):\s+(\d+)", re.M)


def slots_for_memory(meminfo: str) -> int:
    """Сколько дорожек выдержит память (``/proc/meminfo``); 1 — по одной.

    Нечитаемый meminfo — 1: не зная памяти, рисковать роутером нельзя.
    """
    values = {k: int(v) for k, v in _MEMINFO_RE.findall(str(meminfo or ""))}
    if "MemTotal" not in values or "MemAvailable" not in values:
        return 1
    by_free = int((values["MemAvailable"] / 1024.0 - RESERVE_MB) // SLOT_MB)
    by_total = int(values["MemTotal"] / 1024.0 // RAM_PER_SLOT_MB)
    return max(1, min(PAR_MAX, by_free, by_total))


def slot_mark(k: int) -> int:
    return ((k + 1) << 24) & PAR_MASK


def slot_ports(k: int) -> tuple:
    lo = PORT_BASE + k * PORTS_PER_SLOT
    return lo, lo + PORTS_PER_SLOT - 1


def slot_filter(k: int) -> str:
    return "--filter-mark=0x%08x/0x%08x" % (slot_mark(k), PAR_MASK)


def _blob_name(arg: str) -> str:
    return arg[len("--blob="):].split(":", 1)[0].strip()


def combine(args_lists: list) -> tuple:
    """Аргументы кандидатов → argv одного nfqws2 и кто в него вошёл.

    Глобальные опции (``--blob``, ``--lua-init``) поднимаются в начало без
    повторов; кандидат, объявляющий blob с тем же именем, но другим
    содержимым, в пачку не берётся (вернётся в ``alone``). Каждый профиль
    кандидата ``k`` (их может быть несколько — полный пресет с ``--new``)
    начинается с ``--filter-mark`` дорожки ``k``; ``k`` — номер среди
    вошедших.

    Returns:
        (argv, packed, alone): ``packed`` — индексы вошедших в порядке
        дорожек, ``alone`` — индексы тех, кого проверять по одной.
    """
    head, blobs = [], {}
    bodies, packed, alone = [], [], []
    for i, args in enumerate(args_lists):
        globals_, rest = [], []
        for a in args or []:
            (globals_ if a.startswith(_GLOBAL_PREFIXES) else rest).append(a)
        clash = any(a.startswith("--blob=")
                    and blobs.get(_blob_name(a), a) != a for a in globals_)
        if clash or not any(a.startswith("--lua-desync") for a in rest):
            alone.append(i)
            continue
        for a in globals_:
            if a.startswith("--blob="):
                blobs[_blob_name(a)] = a
            if a not in head:
                head.append(a)
        k = len(packed)
        profiles, cur = [], []
        for a in rest:
            if a == "--new":
                if cur:
                    profiles.append(cur)
                cur = []
            else:
                cur.append(a)
        if cur:
            profiles.append(cur)
        bodies.append([[slot_filter(k)] + p for p in profiles])
        packed.append(i)
        if len(packed) >= PAR_MAX:
            alone.extend(range(i + 1, len(args_lists)))
            break
    argv = list(head)
    for profiles in bodies:
        for p in profiles:
            if len(argv) > len(head):
                argv.append("--new")
            argv.extend(p)
    return argv, packed, alone


def enabled(value) -> bool:
    """``scan.parallel`` → включено ли (``auto``/``on``/число > 1)."""
    text = str(value if value is not None else "").strip().lower()
    if text in ("auto", "on", "true", "1", "yes"):
        return text != "1"
    try:
        return int(text) > 1
    except ValueError:
        return False


def limit(value) -> int:
    """Потолок дорожек из ``scan.parallel``: число — оно, иначе PAR_MAX."""
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return PAR_MAX
    return max(1, min(PAR_MAX, n))
