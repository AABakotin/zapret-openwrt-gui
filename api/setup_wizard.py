# api/setup_wizard.py
"""
API пошагового мастера настройки VPN (core/setup_wizard).

  GET  /api/setup-wizard/options         — программы, сервисы, списки, TUN
  GET  /api/setup-wizard/devices         — устройства LAN (без роутера)
  POST /api/setup-wizard/install         — поставить программу {engine, transport?}
  GET  /api/setup-wizard/install/status  — ?engine=… прогресс установки
  POST /api/setup-wizard/apply           — собрать, запустить, маршрут (план)
"""

from bottle import request

from core.log_buffer import log


def _body() -> dict:
    try:
        data = request.json
    except Exception:
        data = None
    return data if isinstance(data, dict) else {}


def register(app):

    @app.route("/api/setup-wizard/options", method="GET")
    def wizard_options():
        from core import setup_wizard
        return setup_wizard.options()

    @app.route("/api/setup-wizard/devices", method="GET")
    def wizard_devices():
        from core import setup_wizard
        return {"ok": True, "devices": setup_wizard.devices()}

    @app.route("/api/setup-wizard/install", method="POST")
    def wizard_install():
        from core import setup_wizard
        body = _body()
        transport = str(body.get("transport") or "").strip()
        if transport and transport != "auto":
            from core.download_transport import is_valid_spec
            if not is_valid_spec(transport):
                return {"ok": False, "error": "Неизвестный транспорт"}
        return setup_wizard.start_install(
            str(body.get("engine") or ""),
            "" if transport == "auto" else transport)

    @app.route("/api/setup-wizard/install/status", method="GET")
    def wizard_install_status():
        from core import setup_wizard
        engine = str(request.query.get("engine") or "")
        if engine not in setup_wizard.ENGINES:
            return {"ok": False, "error": "неизвестная программа"}
        return setup_wizard.install_status(engine)

    @app.route("/api/setup-wizard/apply", method="POST")
    def wizard_apply():
        from core import setup_wizard
        try:
            return setup_wizard.apply(_body())
        except Exception as e:                       # noqa: BLE001
            log.error("мастер: apply упал: %s" % e, source="setup_wizard")
            return {"ok": False, "error": "внутренняя ошибка: %s" % e,
                    "steps": []}
