# api/vpngen.py
"""
API генератора конфигов на инфраструктуре WARP и Proton (core/vpngen).

Эндпоинты:
  GET  /api/vpngen/options          — пресеты, движки, транспорты
  POST /api/vpngen/proton/servers   — бесплатные серверы Proton
                                      {transport?, refresh?}
  POST /api/vpngen/generate         — сгенерировать (и при save — сохранить)
  POST /api/vpngen/save             — сохранить показанный ранее конфиг
                                      {target, name, text}
  POST /api/vpngen/check            — проверить синтаксис {target, text}
                                      или сохранённый {target, name};
                                      target — движок или proton-import

Ответ ``generate`` содержит тексты конфигов с приватными ключами: их
показывает страница генератора, и это ровно то, что пользователь
попросил. Наружу (MCP) тексты уходят только замаскированными —
см. core/mcp/tools/vpngen.py.
"""

from bottle import request

from core.log_buffer import log


def _body() -> dict:
    try:
        data = request.json
    except Exception:
        data = None
    return data if isinstance(data, dict) else {}


def _transport(value) -> tuple:
    """(спека, ошибка) — «auto» или синтаксически правильная спека."""
    spec = str(value or "auto").strip()
    if spec == "auto":
        return spec, ""
    from core.download_transport import is_valid_spec
    if not is_valid_spec(spec):
        return "", "Неизвестный транспорт: %s" % spec
    return spec, ""


def register(app):

    @app.route("/api/vpngen/options", method="GET")
    def vpngen_options():
        from core.vpngen import generate as gen
        return gen.options()

    @app.route("/api/vpngen/proton/servers", method="POST")
    def vpngen_proton_servers():
        from core.vpngen import proton
        from core.vpngen.net import GenError, run_with_transport
        body = _body()
        spec, err = _transport(body.get("transport"))
        if err:
            return {"ok": False, "error": err}
        try:
            data, used, tried = run_with_transport(
                spec, lambda t: proton.servers(
                    t, refresh=bool(body.get("refresh"))))
        except GenError as e:
            # blocked — сервис закрыт для программ: UI предложит импорт.
            return {"ok": False, "error": str(e),
                    "blocked": bool(getattr(e, "blocked", False))}
        except Exception as e:                       # noqa: BLE001
            log.error("vpngen: серверы Proton: %s" % e, source="vpngen")
            return {"ok": False, "error": "внутренняя ошибка: %s" % e}
        countries = sorted({s["country"] for s in data["servers"]
                            if s["country"]})
        return {"ok": True, "servers": data["servers"],
                "countries": countries, "cached": data["cached"],
                "transport": used, "tried": tried}

    @app.route("/api/vpngen/generate", method="POST")
    def vpngen_generate():
        from core.vpngen import generate as gen
        from core.vpngen.net import GenError
        body = _body()
        spec, err = _transport(body.get("transport"))
        if err:
            return {"ok": False, "error": err}
        body["transport"] = spec
        try:
            res = gen.generate(body)
        except GenError as e:
            return {"ok": False, "error": str(e),
                    "blocked": bool(getattr(e, "blocked", False))}
        except Exception as e:                       # noqa: BLE001
            log.error("vpngen: генерация упала: %s" % e, source="vpngen")
            return {"ok": False, "error": "внутренняя ошибка: %s" % e}
        res.pop("secrets", None)
        return res

    @app.route("/api/vpngen/check", method="POST")
    def vpngen_check():
        """Проверить синтаксис конфига (ничего не сохраняет)."""
        from core.vpngen import generate as gen
        from core.vpngen.net import GenError
        body = _body()
        target = str(body.get("target") or "")
        if body.get("text") is None and body.get("name"):
            # Сохранённый конфиг — кнопка «Проверить» в списках движков.
            try:
                text = gen.load_saved(target, str(body.get("name")))
            except (GenError, OSError) as e:
                return {"ok": False, "errors": [str(e)], "checked_by": []}
        else:
            text = str(body.get("text") or "")
        if len(text) > 256 * 1024:
            return {"ok": False, "errors": ["конфиг слишком большой"],
                    "checked_by": []}
        return gen.check_output(target, text)

    @app.route("/api/vpngen/save", method="POST")
    def vpngen_save():
        from core.vpngen import generate as gen
        body = _body()
        target = str(body.get("target") or "")
        name = str(body.get("name") or "").strip()
        text = str(body.get("text") or "")
        if target not in gen.TARGETS:
            return {"ok": False, "error": "неизвестный движок"}
        if not text.strip():
            return {"ok": False, "error": "пустой конфиг"}
        if len(text) > 256 * 1024:
            return {"ok": False, "error": "конфиг слишком большой"}
        return gen.save_output(target, name, text)
