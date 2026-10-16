# core/strategy_refine.py
"""
«Уточнение» стратегии: перебор параметров её фейка вместо всего каталога.

## Зачем

Подбор часто кончается ничем, но не на нуле: одна стратегия прошла TLS и
оборвалась на 16 КБ, другая открыла сайт через раз. Такая «почти рабочая»
обычно доводится не другой стратегией, а другими параметрами того же
фейка: способом обмануть DPI (fooling), числом повторов, подставным именем
сайта или настоящим ClientHello вместо заготовки (приём nfqws2-ui).

Обратная задача — **вариант полегче**: рабочая стратегия с шестью
шагами и ``repeats=20`` грузит роутер и ломается от мелочей; часто
хватает двух шагов.

## Как

1. База — из последнего подбора: в режиме «уточнить» — продвинувшаяся
   дальше всех среди неудачных (наибольший ``score``), «полегче» — лучшая
   рабочая. Из неё берутся шаги ``--lua-desync`` и объявления blob'ов.
2. :func:`mutations` — чистая функция — строит варианты (не больше
   :data:`MAX_VARIANTS`).
3. Варианты уходят в сканер как «своя стратегия» (``custom``): та же
   песочница, тот же шаблон цели, та же перепроверка, а находку можно
   применить из результатов подбора.
"""

from __future__ import annotations

import re

MAX_VARIANTS = 20

# Способы обмануть DPI для фейка (fooling): каждый — отдельный вариант.
FOOLINGS_TCP = ("tcp_md5", "tcp_seq=-10000", "badsum",
                "ip_autottl=-2,3-20", "tcp_ack=-66000")
# Ключи fooling, которые вариант заменяет целиком.
_FOOLING_KEYS = ("tcp_md5", "tcp_seq", "tcp_ack", "tcp_ts", "badsum",
                 "badseq", "ip_ttl", "ip6_ttl", "ip_autottl", "ip6_autottl")
REPEATS = (6, 11, 20)
FAKE_SNI = "www.google.com"
CLONE_BLOB = "ch_clone"
# Функции, у которых есть фейк и параметры фейка.
_FAKE_FNS = ("fake", "fakedsplit", "fakeddisorder", "hostfakesplit")


def _split(step: str) -> tuple:
    """``--lua-desync=fake:a=1:b`` → ("fake", ["a=1", "b"])."""
    body = step.split("=", 1)[1] if "=" in step else step
    parts = body.split(":")
    return parts[0], parts[1:]


def _join(fn: str, opts: list) -> str:
    return "--lua-desync=" + ":".join([fn] + list(opts))


def _key(opt: str) -> str:
    return opt.split("=", 1)[0]


def _set(opts: list, key: str, value=None) -> list:
    """Заменить (или добавить) опцию ``key[=value]``."""
    new = key if value is None else "%s=%s" % (key, value)
    out = [o for o in opts if _key(o) != key]
    return out + [new]


def _blob_of(opts: list) -> str:
    for o in opts:
        if _key(o) == "blob":
            return o.split("=", 1)[1]
    return ""


# Что из профиля базы переносится в варианты. Фильтры (порты, l7,
# списки) подбор ставит свои; а --payload/--in-range/--out-range решают,
# к каким пакетам применяется шаг, — без них вариант отличался бы от базы
# не тем, что написано в его названии.
_KEEP_OPTS = ("--payload", "--in-range", "--out-range")


def _profile_of(args: list, protocol: str) -> list:
    """Профиль базы под протокол подбора (база бывает пресетом из
    нескольких профилей через ``--new``)."""
    from core.strategy_lint import split_profiles
    profiles = [p for p in split_profiles([str(a) for a in args or []])
                if any(a.startswith("--lua-desync=") for a in p)]
    if not profiles:
        return []
    other = "udp" if protocol == "tcp" else "tcp"
    for p in profiles:
        if any(a.startswith("--filter-%s=" % protocol) for a in p):
            return p
    for p in profiles:
        if not any(a.startswith("--filter-%s=" % other) for a in p):
            return p
    return profiles[0]


def split_base(args: list, protocol: str = "tcp") -> tuple:
    """(объявления blob, [[префикс, шаг], …]) профиля базы.

    Префикс шага — опции из :data:`_KEEP_OPTS`, стоящие перед ним: они
    едут вместе с шагом и переходят к следующему, если шаг убран.
    """
    prof = _profile_of(args, protocol)
    decls = [a for a in args or [] if str(a).startswith("--blob=")]
    segs, prefix = [], []
    for a in prof:
        if a.startswith("--lua-desync="):
            segs.append([prefix, a])
            prefix = []
        elif a.split("=", 1)[0] in _KEEP_OPTS:
            prefix.append(a)
    return decls, segs


def _flat(segs: list) -> list:
    out = []
    for prefix, step in segs:
        out += list(prefix) + [step]
    return out


def _replace(segs: list, i: int, step: str) -> list:
    return segs[:i] + [[segs[i][0], step]] + segs[i + 1:]


def _variants_heavier(segs: list, protocol: str) -> list:
    out = []
    steps = [st for _p, st in segs]
    fake_idx = [i for i, st in enumerate(steps) if _split(st)[0] in _FAKE_FNS]
    if not fake_idx:
        # Фейка нет — добавляем его и перебираем уже его параметры.
        blob = "fake_default_quic" if protocol == "udp" else "fake_default_tls"
        extra = "repeats=6" if protocol == "udp" else "tcp_md5:repeats=6"
        added = [[segs[0][0] if segs else [],
                  "--lua-desync=fake:blob=%s:%s" % (blob, extra)]]
        added += [[[] if n == 0 else p, st] for n, (p, st) in enumerate(segs)]
        out.append(("добавить фейк", added))
        out += [("фейк, " + label, var)
                for label, var in _variants_heavier(added, protocol)]
        return out
    i = fake_idx[0]
    fn, opts = _split(steps[i])

    def with_step(new_step):
        return _replace(segs, i, new_step)

    cur_rep = next((o.split("=", 1)[1] for o in opts
                    if _key(o) == "repeats"), "")
    for n in REPEATS:
        if str(n) != cur_rep:
            out.append(("повторов фейка: %d" % n,
                        with_step(_join(fn, _set(opts, "repeats", n)))))
    if protocol == "tcp":
        base = [o for o in opts if _key(o) not in _FOOLING_KEYS]
        for fool in FOOLINGS_TCP:
            k, _, v = fool.partition("=")
            new = _join(fn, _set(base, k, v or None))
            if new != steps[i]:
                out.append(("обман DPI: %s" % fool, with_step(new)))
        if fn == "fake":
            sni = _join(fn, _set(opts, "tls_mod",
                                 "rnd,dupsid,sni=%s" % FAKE_SNI))
            out.append(("подставное имя %s" % FAKE_SNI, with_step(sni)))
            # Настоящий ClientHello клиента вместо заготовки.
            fallback = _blob_of(opts) or "fake_default_tls"
            clone = ("--lua-desync=tls_client_hello_clone:blob=%s:"
                     "fallback=%s" % (CLONE_BLOB, fallback))
            cloned = _join(fn, _set(opts, "blob", CLONE_BLOB))
            out.append(("ClientHello клиента вместо заготовки",
                        segs[:i] + [[segs[i][0], clone], [[], cloned]]
                        + segs[i + 1:]))
            # Самое сильное сочетание — одним вариантом.
            strong = _set(_set(base, "tcp_md5"), "repeats", 11)
            strong = _set(strong, "tls_mod", "rnd,dupsid,sni=%s" % FAKE_SNI)
            out.append(("tcp_md5 + 11 повторов + подставное имя",
                        with_step(_join(fn, strong))))
    return out


def _variants_lighter(segs: list) -> list:
    out = []
    if len(segs) > 1:
        for i, (prefix, st) in enumerate(segs):
            rest = [[p, x] for p, x in segs[:i] + segs[i + 1:]]
            # Префикс убранного шага (--payload…) переходит к следующему.
            if i < len(segs) - 1:
                rest[i] = [list(prefix) + list(rest[i][0]), rest[i][1]]
            out.append(("без шага %s" % _split(st)[0], rest))
    for i, (_prefix, st) in enumerate(segs):
        fn, opts = _split(st)
        rep = next((o.split("=", 1)[1] for o in opts
                    if _key(o) == "repeats"), "")
        if rep.isdigit() and int(rep) > 1:
            lower = max(1, int(rep) // 2)
            new = [o for o in opts if _key(o) != "repeats"]
            if lower > 1:
                new = _set(new, "repeats", lower)
            out.append(("%s: повторов %d вместо %s" % (fn, lower, rep),
                        _replace(segs, i, _join(fn, new))))
        if any(_key(o) == "tls_mod" for o in opts):
            out.append(("%s без tls_mod" % fn, _replace(segs, i, _join(
                fn, [o for o in opts if _key(o) != "tls_mod"]))))
    return out


_NAME_REF_RE = re.compile(r"(?:blob|fallback)=([A-Za-z0-9_]+)")


def mutations(args: list, protocol: str = "tcp", lighter: bool = False,
              limit: int = MAX_VARIANTS) -> list:
    """Варианты стратегии: [{"label", "args"}]. Чистая функция.

    ``args`` — argv стратегии (из пресета — профиль под протокол);
    переносятся шаги ``--lua-desync`` с их ``--payload``/``--*-range`` и
    нужные им объявления blob'ов; фильтр подбор поставит сам. Дубли и
    сама база — вне выдачи. В режиме ``lighter`` первой идёт сама база:
    рабочая не должна пропасть из итогов, если облегчённые не сработают.
    """
    protocol = "udp" if protocol == "udp" else "tcp"
    decls, segs = split_base(args, protocol)
    if not segs:
        return []
    raw = (_variants_lighter(segs) if lighter
           else _variants_heavier(segs, protocol))
    if lighter:
        raw = [("как есть", segs)] + raw
    seen = set() if lighter else {tuple(_flat(segs))}
    out = []
    for label, var in raw:
        flat = _flat(var)
        if not var or tuple(flat) in seen:
            continue
        seen.add(tuple(flat))
        used = {n for s in flat for n in _NAME_REF_RE.findall(s)}
        keep = [d for d in decls
                if d[len("--blob="):].split(":", 1)[0] in used]
        out.append({"label": label, "args": keep + flat})
        if len(out) >= limit:
            break
    return out


def candidates(variants: list) -> list:
    """Варианты → кандидаты сканера (как у «своей стратегии»)."""
    from core.custom_candidates import sid
    return [{"id": sid(v["args"]), "args": v["args"],
             "name": "Уточнение: %s" % v["label"]} for v in variants]


# ───────────────────────────── запуск ─────────────────────────────

def base_from_scan(lighter: bool) -> dict:
    """База из последнего подбора или ``{"error"}``."""
    from core.strategy_scanner import get_strategy_scanner
    sc = get_strategy_scanner()
    base = sc.refine_base(lighter)
    if not base:
        return {"error": ("в последнем подборе нет рабочей стратегии"
                          if lighter else
                          "в последнем подборе нечего уточнять — запустите "
                          "подбор по сайту")}
    return base


def start(lighter: bool = False, stop_after: int = 3) -> dict:
    """Запустить уточнение по итогам последнего подбора."""
    from core import custom_candidates, lint_env
    from core.strategy_scanner import STATUS_RUNNING, get_strategy_scanner
    if get_strategy_scanner().get_status().get("status") == STATUS_RUNNING:
        return {"ok": False, "error": "подбор уже выполняется"}
    base = base_from_scan(lighter)
    if base.get("error"):
        return {"ok": False, "error": base["error"]}
    variants = mutations(base["args"], base["protocol"], lighter)
    if not variants:
        return {"ok": False, "error": "у стратегии «%s» нечего менять"
                                      % base["name"]}
    # Та же отбраковка, что у «своей стратегии»: функция или blob, которых
    # на устройстве нет, — не кандидат.
    known_fn, known_blobs = lint_env.known_functions(), lint_env.known_blobs()
    kept = [c for c in candidates(variants)
            if not custom_candidates.lint_reject(c["args"], known_fn,
                                                 known_blobs)]
    if not kept:
        return {"ok": False, "error": "варианты не прошли проверку функций "
                                      "и blob'ов этого устройства"}
    started = get_strategy_scanner().start(
        target=base["target"], protocol=base["protocol"],
        stop_after=0 if lighter else stop_after,
        confirm=True, custom=kept)
    if not started:
        return {"ok": False, "error": "подбор уже выполняется"}
    return {"ok": True, "base": base["name"], "variants": len(kept),
            "target": base["target"], "lighter": bool(lighter)}
