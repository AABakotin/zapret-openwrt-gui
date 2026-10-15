# core/vpngen/net.py
"""
JSON-запросы генератора — напрямую или через уже работающий обход.

Cloudflare (`api.cloudflareclient.com`) и сервисы-генераторы у нашей
аудитории часто режут: TLS-рукопожатие висит до таймаута. Поэтому
каждый запрос генератора идёт через **транспорт** — ту же спеку, что у
«Качать через» (``core.download_transport``):

    "direct" | "awg:<iface>" | "singbox:<name>" | "mihomo:<name>"

плюс собственное значение ``"auto"``: сначала напрямую, а если сеть не
пустила — по очереди через каждый доступный обход. Какой транспорт
сработал, возвращается вызывающему: пользователь должен видеть, что
регистрация прошла «через AWG: awg0», а не «как-то прошла».
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request

from core.log_buffer import log

TIMEOUT = 25
RETRIES = 2


class GenError(RuntimeError):
    """Ошибка генерации с понятным пользователю текстом.

    ``network=True`` — до сервера не дошли (таймаут, сброс, DNS). Только
    такие ошибки повод пробовать следующий транспорт: ответ 4xx от
    Cloudflare через другой обход не исправится.
    """

    def __init__(self, message: str, *, network: bool = False,
                 status: int = 0, blocked: bool = False):
        super().__init__(message)
        self.network = network
        self.status = status
        # blocked — сервис закрыт владельцем для программ (Cloudflare
        # 1010/1020): UI предлагает импорт готового конфига.
        self.blocked = blocked


def _is_network_error(exc: BaseException) -> bool:
    if isinstance(exc, (socket.timeout, TimeoutError, ssl.SSLError,
                        ConnectionError, socket.gaierror,
                        http.client.HTTPException)):
        # HTTPException: оборванный ответ (IncompleteRead, BadStatusLine)
        # от прокси/обхода — тоже сеть, а не отказ API.
        return True
    if isinstance(exc, urllib.error.URLError) and not isinstance(
            exc, urllib.error.HTTPError):
        return True
    return isinstance(exc, OSError) and not isinstance(
        exc, urllib.error.HTTPError)


def _network_text(host: str, exc: BaseException) -> str:
    reason = getattr(exc, "reason", None) or exc
    text = str(reason) or exc.__class__.__name__
    low = text.lower()
    if isinstance(reason, ssl.SSLError) or "handshake" in low:
        return ("%s: TLS-соединение не устанавливается (%s). Похоже, доступ"
                " режет провайдер — выберите «Через обход» или «Авто»."
                % (host, text))
    if "timed out" in low or isinstance(reason, (socket.timeout,
                                                 TimeoutError)):
        return ("%s не отвечает (таймаут). Попробуйте «Через обход» или"
                " «Авто»." % host)
    return "%s недоступен: %s" % (host, text)


_CF_DENIED = re.compile(r'"error_code"\s*:\s*(10(?:0[5-9]|1[0-2]|20))\b'
                        r'|error code:?\s*(10(?:0[5-9]|1[0-2]|20))\b', re.I)


def _cf_access_denied(text: str) -> str:
    """Код Cloudflare «доступ закрыт» (1005–1012, 1020) или ''."""
    m = _CF_DENIED.search(text or "")
    return (m.group(1) or m.group(2)) if m else ""


def _opener(transport: str):
    if not transport or transport == "direct":
        return urllib.request.build_opener()
    from core.download_transport import build_opener
    try:
        opener = build_opener(transport)
    except RuntimeError as e:
        # Обход пропал (туннель лёг, пока шли прежние попытки) — для
        # «Авто» это как сетевая ошибка: пробуем следующий способ.
        raise GenError(str(e), network=True)
    return opener or urllib.request.build_opener()


def request_json(method: str, url: str, *, body=None, headers=None,
                 transport: str = "direct", timeout: int = TIMEOUT,
                 retries: int = None):
    """Отправить запрос и вернуть разобранный JSON.

    HTTP-ошибки превращаются в ``GenError(status=…)`` с телом ответа
    (Cloudflare объясняет отказ в JSON), HTML вместо JSON — тоже ошибка:
    так выглядит его страница ограничения частоты (код 1015).
    """
    host = urllib.request.urlparse(url).hostname or url
    hdrs = {"Accept": "application/json", "Accept-Encoding": "identity"}
    hdrs.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json; charset=UTF-8")
    opener = _opener(transport)
    if retries is None:
        # Повтор после таймаута безопасен только для чтения: повторный
        # POST /reg оставил бы в Cloudflare лишнее устройство.
        retries = RETRIES if method in ("GET", "HEAD") else 1

    last = None
    for attempt in range(1, max(1, retries) + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs,
                                     method=method)
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                ctype = resp.headers.get("Content-Type", "")
            break
        except urllib.error.HTTPError as e:
            try:
                text = e.read().decode("utf-8", "replace")[:400]
            except Exception:
                text = ""
            blocked = _cf_access_denied(text)
            if blocked:
                # Cloudflare 1010/1020/1006…: владелец сервиса закрыл его
                # для программ (пускает только браузер со своей страницы).
                # Это не блокировка провайдера — обход не поможет, поэтому
                # ошибка не «сетевая» и «Авто» дальше не перебирает.
                raise GenError("%s не принимает запросы от программ"
                               " (Cloudflare %s: доступ закрыт владельцем"
                               " сервиса, обход и VPN тут не помогут)"
                               % (host, blocked), status=e.code,
                               blocked=True)
            if e.code == 429 or "1015" in text:
                raise GenError("%s: слишком много запросов (HTTP %d) —"
                               " подождите несколько минут" % (host, e.code),
                               status=e.code)
            raise GenError("%s ответил HTTP %d: %s"
                           % (host, e.code, _short(text) or e.reason),
                           status=e.code)
        except Exception as e:                      # noqa: BLE001
            if not _is_network_error(e):
                raise GenError("%s: %s" % (host, e))
            last = e
            if attempt < retries:
                time.sleep(1.5 * attempt)
                continue
            raise GenError(_network_text(host, e), network=True)
    else:                                           # pragma: no cover
        raise GenError(_network_text(host, last), network=True)

    if "html" in ctype.lower() and not raw.lstrip().startswith(b"{"):
        raise GenError("%s вернул HTML вместо JSON — сервис перегружен или"
                       " ограничивает частоту запросов" % host)
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise GenError("%s вернул не JSON: %s" % (host, e))


def _short(text: str) -> str:
    """Сообщение об ошибке из JSON-тела ответа, если оно там есть."""
    try:
        data = json.loads(text)
    except ValueError:
        return text.strip()
    if isinstance(data, dict):
        errs = data.get("errors")
        if isinstance(errs, list) and errs:
            first = errs[0]
            if isinstance(first, dict):
                return str(first.get("message") or first)
            return str(first)
        for key in ("error", "message"):
            if data.get(key):
                return str(data[key])
    return text.strip()


def transports_for(spec: str) -> list:
    """Порядок попыток для спеки: ``auto`` — напрямую, потом все обходы."""
    spec = (spec or "auto").strip()
    if spec != "auto":
        return [spec]
    out = ["direct"]
    try:
        from core.download_transport import list_transports
        for item in list_transports().get("transports") or []:
            tid = item.get("id") or ""
            if tid and tid != "direct" and tid not in out:
                out.append(tid)
    except Exception as e:                           # noqa: BLE001
        log.warning("vpngen: список транспортов не получен: %s" % e,
                    source="vpngen")
    return out


def run_with_transport(spec: str, fn):
    """Выполнить ``fn(transport)`` с перебором транспортов.

    Возвращает ``(результат, транспорт, попытки)``. Следующий транспорт
    пробуется только после СЕТЕВОЙ ошибки; ошибка API отдаётся сразу.
    """
    tried = []
    last = None
    for transport in transports_for(spec):
        try:
            result = fn(transport)
            return result, transport, tried
        except GenError as e:
            tried.append({"transport": transport, "error": str(e)})
            last = e
            if not e.network:
                raise
            log.info("vpngen: %s не прошёл (%s), пробуем дальше"
                     % (transport, e), source="vpngen")
    if last is None:
        raise GenError("нет ни одного способа выйти в сеть")
    if len(tried) > 1:
        raise GenError("не удалось ни одним способом: %s" % "; ".join(
            "%s — %s" % (t["transport"], t["error"]) for t in tried),
            network=True)
    raise last
