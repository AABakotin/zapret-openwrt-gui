# core/mcp/redact.py
"""
Вырезание секретов из ответа инструмента.

Применяется в **одной** точке — при сериализации результата
``tools/call`` (``core/mcp/registry.tool_result``). Не в каждом
инструменте: инструментов будет несколько десятков, и «забыли
замаскировать» в одном из них — это утёкший токен, а не мелкая
недоработка.

Как маскируем — **по ключам, а не по значениям**. Поиск «похожего на
секрет» в строках выглядит надёжнее, но в наших ответах живут домены,
аргументы стратегий, lua-выражения и base64-пейлоады: эвристика по
значению съела бы рабочие данные модели, а это тихая порча ответа. Нет
ключа — нет маски.

Что режется:

* ключ подходит под :data:`SECRET_KEY_RE` (``pass|secret|token|key|
  licen|uuid|auth|credential``) — строковое значение заменяется на
  ``***``, словарь/список — целиком;
* булевы значения и числа под такими ключами **не трогаем**:
  ``gui.auth_enabled=true`` секретом не является, а ответ, где половина
  флагов превратилась в ``***``, модель прочитать не может;
* ключ похож на URL подписки (:data:`URL_KEY_RE`) — от адреса остаётся
  ``https://host/…``: хост нужен для диагностики, путь и query — это и
  есть подписка. Адрес не по HTTP (``tg://proxy?…secret=``) проходит
  текстовую чистку: схема другая, а секрет тот же;
* строки под ключами из :data:`TEXT_KEYS` (``stdout``, ``stderr``,
  ``message``, ``error``…) дополнительно прогоняются через
  :func:`redact_text` — туда секрет попадает из внешнего мира, а не из
  нашего конфига.

Чего НЕ режем: домены, hostlist'ы, имена файлов, аргументы nfqws2 — это
рабочие данные, ради которых модель сюда и пришла. Плюс единственное
точечное исключение — :data:`PUBLIC_KEYS` (``confirm_token``): ярлык,
который обязан доехать до модели, иначе подтверждать команды нечем.

:func:`redact_text` вынесена отдельно: ею пользуется S12 (вывод
shell-команд) — там ключей нет, есть сырой текст.

## Режим «без маскировки» (S17)

Маска спасает от утечки, но ломает работу: прочитав конфиг с ``***``
вместо ключа и записав его обратно, модель уничтожает этот ключ. Поэтому
есть **опциональный** режим: разрешение ``secrets`` плюс явный аргумент
``raw: true`` в вызове (см. :func:`core.mcp.registry.call`). Включается
он не флагом в каждой функции, а :func:`unredacted` — переключателем на
время вызова, который живёт в thread-local:

* точка маскировки по-прежнему **одна** — меняется не место вызова, а
  режим;
* ``redact_text`` внутри ``core/shell_exec.py`` и ``tools/files.py``
  зовётся до сериализации, мимо ``tool_result``; флагом в аргументе их
  пришлось бы протаскивать по всей цепочке, а thread-local их
  выключает заодно;
* соседний запрос это не затрагивает: у каждого свой поток bottle.
"""

import re
import threading


MASK = "***"

# Ключи, значение которых наружу не уезжает никогда.
#
# `pass` намеренно с оглядкой назад: без неё под маску уезжали
# `with_bypass`/`without_bypass` (контракт `probe_compare`, S8) и
# `proxy_bypass` — то есть рабочие данные, а не секреты. Подчёркивание
# и начало строки границей считаются, поэтому `password`, `passwd`,
# `passphrase` и `user_pass` маскируются как маскировались.
SECRET_KEY_RE = re.compile(
    r"(?i)(?<![a-z])pass|secret|token|key|licen|uuid|auth|credential")

# Ключи, которые под маску НЕ уходят, хотя и подходят под
# :data:`SECRET_KEY_RE`. Ровно один случай (S12): ``confirm_token`` —
# одноразовый (60 с) ярлык подтверждения, который существует затем,
# чтобы вернуться следующим вызовом. Замаскировав его, мы ничего не
# защищаем — он бесполезен для кого угодно, кроме того, кто его только
# что получил, — зато ломаем двухшаговое подтверждение целиком:
# модель видит «***» и не может подтвердить ни одну команду.
#
# Список именно точечный. Общее правило («поле назвали не так»)
# по-прежнему решается переименованием поля, а не ослаблением маски.
PUBLIC_KEYS = frozenset(("confirm_token",))

# Ключи, в которых лежит URL подписки: оставляем схему и хост.
URL_KEY_RE = re.compile(r"(?i)subscri|(?:^|_)(?:url|link|endpoint)s?$")

# Ключи, под которыми лежит текст из внешнего мира: к нему применяется
# ещё и текстовая чистка (``token=…`` внутри строки).
TEXT_KEYS = frozenset((
    "stdout", "stderr", "output", "command", "cmd", "log", "log_tail",
    "tail", "message", "line", "lines", "errors", "warnings",
    # Сюда приезжает текст ЧУЖИХ программ: последняя строка лога движка
    # (`last_error` в tunnels_status), сообщение упавшего вызова,
    # cmdline постороннего процесса в находке диагностики. Секрет в
    # такой строке — обычное дело (sing-box пишет URL подписки, usque —
    # токен), а ни под одно «секретное» имя ключа она не подходит.
    "error", "last_error", "detail", "diagnostic",
))

# Предохранитель от самодельных циклических структур и слишком глубоких
# ответов: глубже 24 уровней у нас не бывает ничего осмысленного.
MAX_DEPTH = 24

# Правила текстовой чистки: (шаблон, номер группы, которую маскируем).
# Условие на шаблон: склейка ВСЕХ его групп должна давать полное
# совпадение — иначе замена потеряет кусок строки.
_TEXT_RULES = (
    # Authorization: Bearer <...> / Basic <...>
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)?\s*)(\S+)"), 2),
    # token = ..., private_key: ..., password=...
    (re.compile(r"(?i)((?:api[_-]?key|private[_-]?key|public[_-]?key|"
                r"preshared[_-]?key|secret|token|password|passwd|pwd|"
                r"licen[sc]e|credential)s?\s*[:=]\s*)(\"?)"
                r"([^\s\"',;&]+)"), 3),
    # ?token=... в адресе подписки
    (re.compile(r"(?i)([?&](?:token|key|secret|auth|password|"
                r"access[_-]?key)=)([^&\s]+)"), 2),
    # https://user:password@host
    (re.compile(r"(?i)(https?://[^\s:/@]+:)([^\s@/]+)(@)"), 2),
    # vless://UUID@host, trojan://PASSWORD@host, ss://BASE64@host — в
    # ссылке прокси учётные данные стоят ДО @, и это и есть доступ.
    (re.compile(r"(?i)((?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|"
                r"socks5?|anytls|wireguard|wg)://)([^\s@/?#]+)(@)"), 2),
)

# Ключ-значение в JSON (``"password": "…"``) и в YAML/ini-подобном
# тексте (``uuid: …``). Правила выше смотрят на фиксированный список
# слов перед ``=``/``:``, и кавычка между именем и двоеточием их
# ломает: ``cat settings.json`` отдавал токен MCP и пароль GUI
# открытым текстом. Здесь имя ключа проверяется ТЕМ ЖЕ правилом, что у
# структурной маски (:func:`_is_secret_key`), — поэтому текст и dict
# маскируются одинаково, включая исключение ``confirm_token``.
_JSON_PAIR_RE = re.compile(
    r'("([^"\\\n]{1,64})"\s*:\s*")((?:[^"\\\n]|\\.)*)(")')
_YAML_PAIR_RE = re.compile(
    r"(?m)^(\s*(?:-\s+)?([A-Za-z0-9_.\-]{1,64})\s*:[ \t]+)"
    r"([\"']?)([^\s\"'#][^\n#]*?)(\3[ \t]*(?:#.*)?)$")

# Значения, которые маскировать незачем: флаги и числа секретом не
# являются, как и у структурной маски (``auth_enabled: true``).
_PLAIN_VALUE_RE = re.compile(
    r"(?i)^(?:true|false|yes|no|on|off|null|none|~|-?\d+(?:\.\d+)?)$")


# Режим «отдать как есть» — на время одного вызова, в его потоке.
# Значение по умолчанию (маскируем) не зависит ни от какой настройки:
# отсутствие ключа в thread-local — это «маскировать», и так же
# выглядит любой поток, который об этом режиме не знает.
_local = threading.local()


def raw_mode() -> bool:
    """Идёт ли сейчас вызов, которому разрешено отдать секреты как есть."""
    return bool(getattr(_local, "raw", False))


class unredacted:
    """Контекст «не маскировать» для текущего потока.

    Зовётся ровно из одного места — :func:`core.mcp.registry.call`,
    когда включено разрешение ``secrets`` И вызов явно попросил
    ``raw: true``. Вложенность и исключения переживает: прежнее
    значение возвращается в ``__exit__``.
    """

    __slots__ = ("_previous",)

    def __init__(self):
        self._previous = False

    def __enter__(self):
        self._previous = raw_mode()
        _local.raw = True
        return self

    def __exit__(self, exc_type, exc, tb):
        _local.raw = self._previous
        return False


def redact(value, _depth: int = 0, force: bool = False):
    """Вернуть копию ``value`` без секретов.

    Исходная структура не меняется: инструменты отдают куски живого
    конфига, и порча их по дороге обошлась бы дороже утечки.

    ``force=True`` маскирует **несмотря на** режим «без маскировки»:
    так пишется журнал вызовов (``core/mcp/audit.py``). Ответ уезжает
    модели и исчезает, а журнал остаётся на диске и переживает вызов —
    секретам там не место, о чём бы ни попросил клиент.
    """
    if raw_mode() and not force:
        return value
    if _depth > MAX_DEPTH:
        return value

    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            name = str(key)
            if _is_secret_key(name):
                out[key] = _mask_value(item)
            elif isinstance(item, str) and URL_KEY_RE.search(name):
                out[key] = shorten_url(item, force=force)
            elif isinstance(item, str) and name.lower() in TEXT_KEYS:
                out[key] = redact_text(item, force=force)
            else:
                out[key] = redact(item, _depth + 1, force=force)
        return out

    if isinstance(value, (list, tuple)):
        return [redact(item, _depth + 1, force=force) for item in value]

    return value


def redact_text(text: str, force: bool = False) -> str:
    """Замаскировать секреты в сыром тексте (вывод команд, логи).

    Работает по словам-маркерам (``token=``, ``Authorization:``), а не
    по виду значения: иначе под маску попадут домены и аргументы
    стратегий, ради которых текст и запрашивали.

    ``force`` — как у :func:`redact`: журналу маска нужна всегда.
    """
    if raw_mode() and not force:
        return text
    if not isinstance(text, str) or not text:
        return text
    for pattern, index in _TEXT_RULES:
        text = pattern.sub(lambda m, i=index: _join_masked(m, i), text)
    text = _JSON_PAIR_RE.sub(_mask_json_pair, text)
    text = _YAML_PAIR_RE.sub(_mask_yaml_pair, text)
    return text


def shorten_url(value: str, force: bool = False) -> str:
    """Оставить от адреса схему и хост: ``https://host/…``.

    Подписка — это путь и query; хост оставляем, потому что по нему
    видно, куда ходит GUI, и это сама по себе полезная диагностика.
    """
    if raw_mode() and not force:
        return value
    if not isinstance(value, str):
        return value
    text = value.strip()
    lowered = text.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        # Не HTTP — но и не обязательно безобидно: `tg://proxy?…secret=`
        # это готовый доступ к прокси, а «ключ похож на URL» про схему
        # ничего не обещает. Отдаём такой адрес через текстовую чистку.
        return redact_text(value, force=force)
    scheme, _, rest = text.partition("://")
    host = rest.split("/", 1)[0].split("?", 1)[0]
    if "@" in host:                       # user:pass@host
        host = host.rsplit("@", 1)[1]
    if len(rest) <= len(host):
        return "%s://%s" % (scheme, host)
    return "%s://%s/…" % (scheme, host)


def mask_written_back(new_text, old_text=None) -> bool:
    """Похоже ли, что запись несёт обратно нашу же маску.

    Модель читает конфиг с ``***`` вместо ключа, правит соседнюю строку
    и сохраняет текст целиком — ключ уничтожен, а в ответе «сохранено».
    Подсказка в ответе чтения это не останавливает: её можно не
    прочесть. Поэтому пишущие инструменты спрашивают здесь: маска
    появилась там, где её раньше не было, — значит, это не содержимое,
    а след маскировки.
    """
    if not isinstance(new_text, str) or MASK not in new_text:
        return False
    return not (isinstance(old_text, str) and MASK in old_text)


MASK_WRITE_HINT = ("в записываемом тексте есть «%s» — это маска секретов "
                   "из ответа чтения, а не значение: записав её, вы "
                   "уничтожите настоящие ключи и пароли. Прочитайте "
                   "содержимое с raw=true (разрешение «secrets») и "
                   "пишите полный текст" % MASK)


def is_secret_key(name: str) -> bool:
    """Публичная проверка: считается ли такой ключ секретным.

    Нужна модели путей (``core/mcp/permissions.py``): секретное поле не
    только не отдаётся наружу, но и не принимается на запись.
    """
    return _is_secret_key(str(name))


# ───────────────────────────── частности ────────────────────────────

def _is_secret_key(name: str) -> bool:
    if name.lower() in PUBLIC_KEYS:
        return False
    return bool(SECRET_KEY_RE.search(name))


def _mask_value(item):
    """Чем заменить значение секретного ключа.

    ``bool`` и числа пропускаем: флаг ``auth_enabled`` секретом не
    является, а ответ из одних ``***`` нечитаем. Всё остальное —
    строки, словари, списки — заменяется целиком.
    """
    if isinstance(item, bool) or item is None:
        return item
    if isinstance(item, (int, float)):
        return item
    if isinstance(item, str):
        return MASK if item else item
    return MASK


def _mask_json_pair(match) -> str:
    """``"имя": "значение"`` — маска, если имя секретное."""
    head, name, value, tail = match.group(1, 2, 3, 4)
    if not value or value == MASK or not _is_secret_key(name):
        return match.group(0)
    return head + MASK + tail


def _mask_yaml_pair(match) -> str:
    """``имя: значение`` в начале строки — маска, если имя секретное."""
    head, name, quote, value, tail = match.group(1, 2, 3, 4, 5)
    value = value.rstrip()
    if (not value or value == MASK or _PLAIN_VALUE_RE.match(value)
            or not _is_secret_key(name)):
        return match.group(0)
    return head + quote + MASK + tail


def _join_masked(match, index: int) -> str:
    """Склеить группы совпадения, заменив ``index``-ю на маску."""
    parts = []
    for number, group in enumerate(match.groups(), 1):
        if group is None:
            continue
        parts.append(MASK if number == index else group)
    return "".join(parts)
