# core/custom_candidates.py
"""
«Своя стратегия» в подборе: текст из чата → кандидаты сканера.

## Зачем

Стратегии гуляют по чатам и форумам: в кавычках-«ёлочках», с подписью
«у меня на Ростелекоме работает», целой командой ``nfqws2 …`` или
строкой ``NFQWS2_OPT="…"``. Человек хочет проверить именно их — на своём
провайдере и своём сайте, — а не перебирать каталог (приём nfqws2-ui).

## Что берётся

Вставленный текст режется на части по ``--new`` и пустым строкам; каждая
часть — отдельный кандидат, не больше :data:`MAX_CANDIDATES`. Из части
берутся **только шаги** ``--lua-desync=…``: фильтры (порты, l7,
хостлисты), пути к файлам и опции движка у чужого роутера свои, а
шаблон цели подбор подставляет сам — как для приёмов из каталога.

Часть с фильтром только по другому протоколу (``--filter-udp`` при
подборе для TCP) пропускается с объяснением. Стратегии nfqws v1
(``--dpi-desync``) не переводятся — называются.

## До запуска

Неизвестная функция ``--lua-desync`` и необъявленный blob — ошибка,
которая в движке проявляется молча (стратегия «работает», но ничего не
делает). Поэтому такие кандидаты отбрасываются ДО прогона, с причиной;
линтер тот же, что у MCP (``core/strategy_lint.py``).

Разбор — чистые функции; окружение (функции и blob'ы устройства)
приходит аргументами (``core/lint_env.py``).
"""

from __future__ import annotations

import hashlib
import re

MAX_CANDIDATES = 10
# Сколько текста вообще принимать: это поле формы, а не файл.
MAX_TEXT = 20000

# Кавычки, которые приносит копирование из мессенджеров и вордов.
_QUOTES = "\"'`“”„«»‘’‚"
_TOKEN_RE = re.compile(
    r"--new\b|--lua-desync=[^\s" + re.escape(_QUOTES) + r"]+"
    r"|--blob=\S+|--filter-(?:tcp|udp|l7)=\S*|--payload=\S*"
    r"|--dpi-desync\S*")
# l7 / payload → протокол: по ним часть без портов тоже видно.
_UDP_L7 = ("quic", "stun", "discord", "wireguard", "dht")
_TCP_L7 = ("tls", "http")
_BLOB_REF_RE = re.compile(r"(?<!-)blob=([A-Za-z0-9_]+)")
_BLANK_RE = re.compile(r"\n[ \t]*\n")
_REJECT_CODES = ("unknown_lua_function", "blob_unknown", "blob_file_missing")


def _clean(text: str) -> str:
    text = str(text or "").replace("\r\n", "\n")
    # «\» в конце строки — перенос команды, а не граница стратегии.
    text = re.sub(r"\\\n", " ", text)
    # --lua-desync="…": кавычка сразу после «=» — часть значения;
    # остальные кавычки — границы, как пробел.
    text = re.sub("=[" + re.escape(_QUOTES) + "]+", "=", text)
    for q in _QUOTES:
        text = text.replace(q, " ")
    return text


def _new_part() -> dict:
    return {"desync": [], "tcp": False, "udp": False, "v1": False}


def _mark_l7(part: dict, value: str) -> None:
    for v in value.lower().split(","):
        if any(v.startswith(x) for x in _UDP_L7):
            part["udp"] = True
        elif any(v.startswith(x) for x in _TCP_L7):
            part["tcp"] = True


def split_parts(text: str) -> tuple:
    """(части, blob'ы) текста.

    Часть — {"desync": [...], "tcp", "udp", "v1"}; граница — ``--new`` и
    пустая строка; часть без шагов ``--lua-desync`` в выдачу не попадает
    (кроме стратегии v1 — её надо назвать). Протокол части — по
    ``--filter-tcp/udp``, ``--filter-l7`` и ``--payload``.

    blob'ы — объявления ``--blob=имя:…`` со всего текста (они глобальные):
    ``{имя: аргумент}`` для инлайнового hex и ``{имя: None}`` для файла —
    путь чужого роутера у нас ничего не значит.
    """
    parts, blobs = [], {}
    for block in _BLANK_RE.split(_clean(text)):
        cur = _new_part()
        for tok in _TOKEN_RE.findall(block):
            if tok == "--new":
                parts.append(cur)
                cur = _new_part()
            elif tok.startswith("--lua-desync="):
                cur["desync"].append(tok)
            elif tok.startswith("--blob="):
                name, _, value = tok[len("--blob="):].partition(":")
                if name:
                    blobs[name] = tok if value.lower().startswith("0x") \
                        else None
            elif tok.startswith("--filter-tcp="):
                cur["tcp"] = True
            elif tok.startswith("--filter-udp="):
                cur["udp"] = True
            elif tok.startswith(("--filter-l7=", "--payload=")):
                _mark_l7(cur, tok.split("=", 1)[1])
            else:
                cur["v1"] = True
        parts.append(cur)
    return [p for p in parts if p["desync"] or p["v1"]], blobs


def _sid(desync: list) -> str:
    digest = hashlib.sha1(" ".join(desync).encode("utf-8")).hexdigest()
    return "custom_" + digest[:10]


def check(text: str, protocol: str = "tcp", known_functions=None,
          known_blobs=None) -> dict:
    """Разобрать текст: что пойдёт в подбор, что нет и почему.

    Returns:
        {"ok", "candidates": [{"id", "args", "index"}],
         "rejected": [{"index", "args", "reason"}], "dropped": int,
         "error"?}
    """
    from core import strategy_lint

    protocol = "udp" if str(protocol).lower() == "udp" else "tcp"
    if len(str(text or "")) > MAX_TEXT:
        return {"ok": False, "candidates": [], "rejected": [], "dropped": 0,
                "protocol": protocol,
                "error": "текст длиннее %d знаков — вставьте только "
                         "стратегии" % MAX_TEXT}
    candidates, rejected, seen = [], [], {}
    dropped = 0
    parts, blobs = split_parts(text)
    for index, part in enumerate(parts, 1):
        args = part["desync"]
        if not args:
            rejected.append({"index": index, "args": [], "reason": (
                "стратегия nfqws v1 (--dpi-desync) — для nfqws2 её надо "
                "переписать на --lua-desync")})
            continue
        if part["udp"] and not part["tcp"] and protocol == "tcp":
            rejected.append({"index": index, "args": args,
                             "reason": "часть для UDP — подбор идёт по TCP"})
            continue
        if part["tcp"] and not part["udp"] and protocol == "udp":
            rejected.append({"index": index, "args": args,
                             "reason": "часть для TCP — подбор идёт по UDP"})
            continue
        key = tuple(args)
        if key in seen:
            rejected.append({"index": index, "args": args,
                             "reason": "повтор части %d" % seen[key]})
            continue
        seen[key] = index
        refs = {n for a in args for n in _BLOB_REF_RE.findall(a)}
        foreign = sorted(n for n in refs if n in blobs and blobs[n] is None)
        if foreign:
            rejected.append({"index": index, "args": args, "reason": (
                "blob «%s» читается из файла чужого роутера — загрузите "
                "его в «Блобы» и сошлитесь на имя оттуда" % foreign[0])})
            continue
        # Инлайновый blob (``--blob=имя:0x…``) переносим вместе с частью.
        args = [blobs[n] for n in sorted(refs) if blobs.get(n)] + args
        findings = [f for f in strategy_lint.lint(
            args, known_functions=known_functions, known_blobs=known_blobs)
            if f.get("code") in _REJECT_CODES]
        if findings:
            rejected.append({"index": index, "args": args,
                             "reason": findings[0]["message"]})
            continue
        if len(candidates) >= MAX_CANDIDATES:
            dropped += 1
            continue
        candidates.append({"id": _sid(args), "args": args, "index": index})
    out = {"ok": bool(candidates), "candidates": candidates,
           "rejected": rejected, "dropped": dropped,
           "protocol": protocol}
    if not candidates:
        out["error"] = ("не нашлось ни одного шага --lua-desync, который "
                        "можно проверить" if not rejected else
                        "все части отброшены — причины в списке")
    return out


def entries(candidates: list, protocol: str = "tcp") -> list:
    """Кандидаты → CatalogEntry для сканера (шаблон цели он подставит)."""
    from core.models import CatalogEntry
    out = []
    for n, c in enumerate(candidates, 1):
        out.append(CatalogEntry(
            section_id=c["id"],
            name="Своя стратегия %d" % n,
            description="вставлена пользователем",
            author="user",
            label="custom",
            blobs=[],
            args="\n".join(c["args"]),
            protocol=protocol,
            level="custom",
            source_file="custom",
        ))
    return out


def check_on_device(text: str, protocol: str = "tcp") -> dict:
    """:func:`check` с функциями и blob'ами ЭТОГО устройства (REST и MCP)."""
    from core import lint_env
    return check(text, protocol, known_functions=lint_env.known_functions(),
                 known_blobs=lint_env.known_blobs())
