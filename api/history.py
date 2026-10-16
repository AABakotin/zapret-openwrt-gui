# api/history.py
"""
REST API истории файлов и применения стратегии с проверкой.

История (core/file_history.py):
  GET  /api/history                 — версии по действиям (?file=, ?limit=)
  GET  /api/history/diff?id=N       — разница версии с предыдущей
  POST /api/history/restore         — {id, side: before|after} вернуть файл
  POST /api/history/undo            — отменить последнее действие
  POST /api/history/scan            — сверить с диском сейчас (правки вне GUI)

Применение с проверкой (core/safe_apply.py):
  GET  /api/safe-apply              — текущая проверка и рабочая точка
  POST /api/safe-apply/start        — {strategy_id, timeout?}
  POST /api/safe-apply/confirm      — «Всё работает»
  POST /api/safe-apply/rollback     — «Откатить»
  POST /api/safe-apply/mark-working — отметить текущее состояние рабочим
  POST /api/safe-apply/restore-working — «Вернуть рабочее состояние»
"""

from bottle import request, response


def _json_body():
    try:
        return request.json or {}
    except Exception:
        return {}


def register(app):

    @app.route("/api/history")
    def api_history_list():
        response.content_type = "application/json; charset=utf-8"
        from core import file_history
        try:
            limit = max(1, min(500, int(request.params.get("limit") or 100)))
        except ValueError:
            limit = 100
        out = file_history.list_entries(file=request.params.get("file", ""),
                                        limit=limit)
        out["enabled"] = file_history.enabled()
        return out

    @app.route("/api/history/diff")
    def api_history_diff():
        response.content_type = "application/json; charset=utf-8"
        from core import file_history
        return file_history.diff(request.params.get("id"))

    @app.route("/api/history/restore", method="POST")
    def api_history_restore():
        response.content_type = "application/json; charset=utf-8"
        from core import file_history
        body = _json_body()
        side = "after" if body.get("side") == "after" else "before"
        return file_history.restore(body.get("id"), side=side)

    @app.route("/api/history/undo", method="POST")
    def api_history_undo():
        response.content_type = "application/json; charset=utf-8"
        from core import file_history
        return file_history.undo_last()

    @app.route("/api/history/scan", method="POST")
    def api_history_scan():
        response.content_type = "application/json; charset=utf-8"
        from core import file_history
        return file_history.scan()

    @app.route("/api/safe-apply")
    def api_safe_apply_status():
        response.content_type = "application/json; charset=utf-8"
        from core import safe_apply
        return safe_apply.status()

    @app.route("/api/safe-apply/start", method="POST")
    def api_safe_apply_start():
        response.content_type = "application/json; charset=utf-8"
        from core import safe_apply
        body = _json_body()
        sid = str(body.get("strategy_id") or "").strip()
        if not sid:
            response.status = 400
            return {"ok": False, "error": "не указана стратегия"}
        return safe_apply.start(sid, body.get("timeout")
                                or safe_apply.DEFAULT_TIMEOUT)

    @app.route("/api/safe-apply/confirm", method="POST")
    def api_safe_apply_confirm():
        response.content_type = "application/json; charset=utf-8"
        from core import safe_apply
        return safe_apply.confirm()

    @app.route("/api/safe-apply/rollback", method="POST")
    def api_safe_apply_rollback():
        response.content_type = "application/json; charset=utf-8"
        from core import safe_apply
        return safe_apply.cancel()

    @app.route("/api/safe-apply/mark-working", method="POST")
    def api_safe_apply_mark():
        response.content_type = "application/json; charset=utf-8"
        from core import safe_apply
        return safe_apply.mark_working(str(_json_body().get("note") or ""))

    @app.route("/api/safe-apply/restore-working", method="POST")
    def api_safe_apply_restore():
        response.content_type = "application/json; charset=utf-8"
        from core import safe_apply
        return safe_apply.restore_working()
