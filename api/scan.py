# api/scan.py
"""
API подбора стратегий (Strategy Scanner).

Эндпоинты:
  POST /api/scan/start          — начать подбор стратегий
  GET  /api/scan/status         — прогресс подбора
  POST /api/scan/stop           — остановить подбор
  GET  /api/scan/results        — результаты подбора
  POST /api/scan/apply/<idx>    — применить найденную стратегию по индексу
  POST /api/scan/custom/check   — разобрать «свою стратегию» до запуска
  POST /api/scan/refine         — «уточнение» лучшей попытки / вариант полегче
  POST /api/scan/freeze/start   — проба «обрыв на 16 КБ» по сетям хостингов
  POST /api/scan/freeze/stop    — остановить пробу
  GET  /api/scan/freeze         — ход пробы или итог прошлой
  POST /api/scan/freeze/apply   — приём сети профилем на её IP-список
"""

from bottle import request, response


def register(app):

    @app.post("/api/scan/start")
    def api_scan_start():
        """
        Начать подбор стратегий.

        Body (JSON):
            {
                "target": "youtube.com",                    (обязательно)
                "protocol": "tcp" | "udp",                  (опционально, default: tcp)
                "mode": "quick" | "standard" | "full",      (опционально, default: quick)
                "resume": true | false,                      (опционально, default: false)
                "stop_after": 0..50,                         (опционально, 0 — перебрать всё)
                "confirm": true | false,                     (опционально, default: true)
                "custom": "текст из чата"                    (опционально: «своя
                                                              стратегия» вместо каталога)
            }
        """
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_scanner import get_strategy_scanner

        scanner = get_strategy_scanner()

        # Парсим тело запроса
        try:
            body = request.json or {}
        except Exception:
            body = {}

        target = (body.get("target") or "").strip()
        if not target:
            response.status = 400
            return {
                "ok": False,
                "error": "Поле 'target' обязательно (домен для проверки)",
            }

        # Базовая валидация домена
        import re
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]+$', target):
            response.status = 400
            return {
                "ok": False,
                "error": "Невалидный домен: %s" % target,
            }

        protocol = body.get("protocol", "tcp")
        if protocol not in ("tcp", "udp"):
            response.status = 400
            return {
                "ok": False,
                "error": "Неверный протокол: %s. "
                         "Допустимые: tcp, udp" % protocol,
            }

        custom = None
        if str(body.get("custom") or "").strip():
            checked = _check_custom(body.get("custom"), protocol)
            if not checked["ok"]:
                response.status = 400
                return checked
            custom = checked["candidates"]

        mode = body.get("mode", "quick")
        if custom is None and mode not in ("quick", "standard", "full"):
            response.status = 400
            return {
                "ok": False,
                "error": "Неверный режим: %s. "
                         "Допустимые: quick, standard, full" % mode,
            }

        # DPI-type фильтрация (опционально, из BlockCheck)
        dpi_type = (body.get("dpi_type") or "").strip().lower()

        # Остановиться после N рабочих (0 — перебрать всё) и перепроверка
        # лучших находок.
        try:
            stop_after = int(body.get("stop_after") or 0)
        except (TypeError, ValueError):
            stop_after = -1
        if not 0 <= stop_after <= 50:
            response.status = 400
            return {
                "ok": False,
                "error": "stop_after — число от 0 до 50 (0 — перебрать всё)",
            }
        confirm = body.get("confirm", True) is not False

        # Resume: индекс из сохранённого состояния — только если это тот
        # же прогон (иначе позиция чужого списка стратегий).
        resume = bool(body.get("resume", False)) and custom is None
        start_index = 0
        if resume:
            start_index = scanner.get_resume_index(
                target=target, protocol=protocol, mode=mode,
                dpi_type=dpi_type)

        # Запускаем
        started = scanner.start(
            target=target,
            protocol=protocol,
            mode=mode,
            start_index=start_index,
            dpi_type=dpi_type,
            stop_after=stop_after,
            confirm=confirm,
            custom=custom,
            # Нет в запросе — по настройке scan.parallel.
            parallel=(bool(body["parallel"]) if "parallel" in body
                      else None),
        )

        if not started:
            response.status = 409
            return {
                "ok": False,
                "error": "Подбор стратегий уже выполняется",
            }

        result = {
            "ok": True,
            "status": "started",
            "target": target,
            "protocol": protocol,
            "mode": "custom" if custom else mode,
        }
        if custom:
            result["custom"] = checked
        if resume and start_index > 0:
            result["resumed_from"] = start_index

        return result

    @app.post("/api/scan/refine")
    def api_scan_refine():
        """«Уточнение» по итогам последнего подбора.

        Body: {"lighter": false} — уточнить почти рабочую (параметры
        фейка); true — искать вариант полегче для рабочей.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core import strategy_refine
        res = strategy_refine.start(lighter=bool(body.get("lighter")))
        if not res.get("ok"):
            response.status = 409 if "выполняется" in res.get("error", "") \
                else 400
        return res

    @app.post("/api/scan/freeze/start")
    def api_scan_freeze_start():
        """Проба «обрыв на 16 КБ»: где обрыв и какое имя в фейке его снимает."""
        response.content_type = "application/json; charset=utf-8"
        from core import freeze_probe
        res = freeze_probe.start()
        if not res.get("ok"):
            response.status = 409
        return res

    @app.post("/api/scan/freeze/stop")
    def api_scan_freeze_stop():
        response.content_type = "application/json; charset=utf-8"
        from core import freeze_probe
        return freeze_probe.stop()

    @app.route("/api/scan/freeze")
    def api_scan_freeze():
        response.content_type = "application/json; charset=utf-8"
        from core import freeze_probe
        return {"ok": True, **freeze_probe.status()}

    @app.post("/api/scan/freeze/apply")
    def api_scan_freeze_apply():
        """«Применить для сети». Body: {"asn": "24940"}."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core import freeze_probe
        res = freeze_probe.apply_network(str(body.get("asn") or ""))
        if not res.get("ok"):
            response.status = 400
        return res

    @app.post("/api/scan/custom/check")
    def api_scan_custom_check():
        """«Своя стратегия»: что пойдёт в подбор, что отброшено и почему.

        Body: {"text": "…", "protocol": "tcp" | "udp"}
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        protocol = body.get("protocol", "tcp")
        if protocol not in ("tcp", "udp"):
            protocol = "tcp"
        return _check_custom(body.get("text"), protocol)

    @app.route("/api/scan/status")
    def api_scan_status():
        """Текущий статус и прогресс подбора."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_scanner import get_strategy_scanner

        scanner = get_strategy_scanner()
        status = scanner.get_status()

        return {"ok": True, **status}

    @app.route("/api/scan/generated")
    def api_scan_generated():
        """Предпросмотр стратегий, сгенерированных «на лету».

        Query: ?protocol=tcp|udp & level=quick|standard|full
        Возвращает упорядоченный (от простых к сложным) список без запуска
        самого подбора — для UI/диагностики.
        """
        from bottle import request as _req
        response.content_type = "application/json; charset=utf-8"

        protocol = (_req.query.get("protocol") or "tcp").lower()
        level = (_req.query.get("level") or "standard").lower()

        try:
            from core.strategy_generator import generate, complexity_key
            entries = generate(protocol=protocol, level=level)
            items = [
                {
                    "id": e.section_id,
                    "name": e.name,
                    "description": e.description,
                    "args": e.get_args_list(),
                    "complexity": list(complexity_key(e.get_args_list())),
                }
                for e in entries
            ]
            return {"ok": True, "protocol": protocol, "level": level,
                    "count": len(items), "strategies": items}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)[:200]}

    @app.route("/api/scan/results")
    def api_scan_results():
        """Результаты подбора стратегий."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_scanner import get_strategy_scanner

        scanner = get_strategy_scanner()

        # Работающие стратегии
        working = scanner.get_working_strategies()

        # Полный отчёт если есть
        report = scanner.get_results()
        report_dict = report.to_dict() if report else None

        return {
            "ok": True,
            "working": working,
            "working_count": len(working),
            "report": report_dict,
        }

    @app.post("/api/scan/stop")
    def api_scan_stop():
        """Остановить текущий подбор."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_scanner import get_strategy_scanner

        scanner = get_strategy_scanner()

        # FIX: было scanner.cancel() — такого метода нет,
        # правильный метод: stop()
        stopped = scanner.stop()

        if not stopped:
            return {
                "ok": True,
                "message": "Подбор не выполняется",
            }

        return {
            "ok": True,
            "message": "Остановка запрошена",
        }

    @app.post("/api/scan/apply/<idx:int>")
    def api_scan_apply(idx):
        """
        Применить найденную стратегию по индексу.

        Создаёт user-стратегию в JSON и перезапускает nfqws2.
        """
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_scanner import get_strategy_scanner
        from core.log_buffer import log

        scanner = get_strategy_scanner()

        applied = scanner.apply_strategy(idx)

        if not applied:
            response.status = 400
            return {
                "ok": False,
                "error": "Не удалось применить стратегию с индексом %d. "
                         "Проверьте, что индекс корректен." % idx,
            }

        log.success(
            "Стратегия из подбора #%d применена" % idx,
            source="scan-api",
        )

        return {
            "ok": True,
            "message": "Стратегия применена",
        }


def _check_custom(text, protocol) -> dict:
    """Разбор «своей стратегии» с окружением этого устройства."""
    from core.custom_candidates import check_on_device
    return check_on_device(text, protocol)
