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

import hashlib
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


def split_base(args: list) -> tuple:
    """(объявления blob, шаги --lua-desync) из argv стратегии."""
    decls = [a for a in args if str(a).startswith("--blob=")]
    steps = [a for a in args if str(a).startswith("--lua-desync=")]
    return decls, steps


def _variants_heavier(steps: list, protocol: str) -> list:
    out = []
    fake_idx = [i for i, s in enumerate(steps) if _split(s)[0] in _FAKE_FNS]
    if not fake_idx:
        # Фейка нет вовсе — сначала пробуем его добавить.
        blob = "fake_default_quic" if protocol == "udp" else "fake_default_tls"
        extra = "repeats=6" if protocol == "udp" else "tcp_md5:repeats=6"
        out.append(("добавить фейк", ["--lua-desync=fake:blob=%s:%s"
                                      % (blob, extra)] + steps))
        return out
    i = fake_idx[0]
    fn, opts = _split(steps[i])

    def with_step(new_step):
        return steps[:i] + [new_step] + steps[i + 1:]

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
                        steps[:i] + [clone, cloned] + steps[i + 1:]))
            # Самое сильное сочетание — одним вариантом.
            strong = _set(_set(base, "tcp_md5"), "repeats", 11)
            strong = _set(strong, "tls_mod", "rnd,dupsid,sni=%s" % FAKE_SNI)
            out.append(("tcp_md5 + 11 повторов + подставное имя",
                        with_step(_join(fn, strong))))
    return out


def _variants_lighter(steps: list) -> list:
    out = []
    if len(steps) > 1:
        for i, s in enumerate(steps):
            rest = steps[:i] + steps[i + 1:]
            out.append(("без шага %s" % _split(s)[0], rest))
    for i, s in enumerate(steps):
        fn, opts = _split(s)
        rep = next((o.split("=", 1)[1] for o in opts
                    if _key(o) == "repeats"), "")
        if rep.isdigit() and int(rep) > 1:
            lower = max(1, int(rep) // 2)
            new = [o for o in opts if _key(o) != "repeats"]
            if lower > 1:
                new = _set(new, "repeats", lower)
            out.append(("%s: повторов %d вместо %s" % (fn, lower, rep),
                        steps[:i] + [_join(fn, new)] + steps[i + 1:]))
        if any(_key(o) == "tls_mod" for o in opts):
            out.append(("%s без tls_mod" % fn, steps[:i] + [_join(
                fn, [o for o in opts if _key(o) != "tls_mod"])]
                + steps[i + 1:]))
    return out


def mutations(args: list, protocol: str = "tcp", lighter: bool = False,
              limit: int = MAX_VARIANTS) -> list:
    """Варианты стратегии: [{"label", "args"}]. Чистая функция.

    ``args`` — argv стратегии; берутся объявления blob'ов и шаги
    ``--lua-desync`` (фильтр подбор поставит сам). Дубли и сама база —
    вне выдачи.
    """
    protocol = "udp" if protocol == "udp" else "tcp"
    decls, steps = split_base([str(a) for a in args or []])
    if not steps:
        return []
    raw = (_variants_lighter(steps) if lighter
           else _variants_heavier(steps, protocol))
    seen = {tuple(steps)}
    out = []
    for label, var in raw:
        if not var or tuple(var) in seen:
            continue
        seen.add(tuple(var))
        used = {n for s in var for n in re.findall(r"blob=([A-Za-z0-9_]+)",
                                                   s)}
        keep = [d for d in decls
                if d[len("--blob="):].split(":", 1)[0] in used]
        out.append({"label": label, "args": keep + var})
        if len(out) >= limit:
            break
    return out


def candidates(variants: list) -> list:
    """Варианты → кандидаты сканера (как у «своей стратегии»)."""
    out = []
    for v in variants:
        digest = hashlib.sha1(" ".join(v["args"]).encode()).hexdigest()
        out.append({"id": "custom_" + digest[:10], "args": v["args"],
                    "name": "Уточнение: %s" % v["label"]})
    return out


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
    from core.strategy_scanner import get_strategy_scanner
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
