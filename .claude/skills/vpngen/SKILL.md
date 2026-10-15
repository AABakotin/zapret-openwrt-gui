---
name: vpngen
description: >-
  Генератор VPN-конфигов на инфраструктуре Cloudflare WARP и Proton VPN и
  пошаговый мастер настройки в проекте zapret-gui (роутеры Keenetic на
  Entware / OpenWrt / Linux). Использовать при любых задачах о: нативной
  регистрации устройства WARP в API Cloudflare (api.cloudflareclient.com
  v0a4471, тела POST /reg и PATCH /reg/<id>, WARP+ ключ PUT /account,
  client_id → reserved), переключении устройства на MASQUE (curve25519 →
  secp256r1/masque, как `usque register`), бесплатных серверах Proton через
  сервис proton-generation (сессия, /servers, сертификат на Ed25519, ключ
  WireGuard из того же скаляра), сервисах-генераторах warp-generation
  (warp-api.cfd, режим source=service), ключах на чистом Python (X25519 RFC
  7748, Ed25519 RFC 8032, P-256 с DER SEC1/SPKI как у Go x509), транспорте
  «напрямую / через обход / авто» (core/download_transport, перебор только
  по сетевым ошибкам), пресетах (DNS, адреса и порты Cloudflare WARP, порты
  Proton, AllowedIPs без LAN, маски I1: QUIC Initial с SNI, DNS-запрос, SIP),
  совместимости AmneziaWG с ванильным WireGuard-сервером (S1..S4=0,
  H1..H4=1..4, только Jc/Jmin/Jmax и I1..I5), рендерах под AmneziaWG
  (.conf), usque (config.json), sing-box (WireGuard в endpoints, 1.11+) и
  mihomo (wireguard + amnezia-wg-option, type masque с fallback H3→H2),
  сохранении без перезаписи и подборе имён/портов, API /api/vpngen/*,
  MCP-инструментах vpngen_options / vpngen_proton_servers / vpngen_generate
  (маскировка ключей, откат удаляет созданное), странице «Генератор
  конфигов» (web/js/pages/vpngen.js), мастере настройки (core/setup_wizard.py,
  /api/setup-wizard/*, web/js/pages/setup_wizard.js: программа → установка →
  сервер → что пускать → запуск; TUN-конфиги sing-box/mihomo без auto_route,
  маршрут единого слоя awg:/warp:/singbox:/mihomo:, «все устройства»
  поштучно), общем компоненте Wizard (web/js/components/wizard.js) и
  диагностике «регистрация не проходит / TLS handshake timeout / 429 / туннель
  поднялся, но трафика нет». Источники истины — Diniboy1123/usque
  (api/cloudflare.go, internal/consts.go), MetaCubeX/mihomo
  (adapter/outbound/masque.go, wireguard.go), sing-box (endpoints), клиентский
  код warp-generation и proton-generation; привязка — core/vpngen/*,
  core/setup_wizard.py, api/vpngen.py, api/setup_wizard.py,
  core/mcp/tools/vpngen.py.
---

# Генератор конфигов WARP/Proton и мастер настройки

Две связанные вещи:

* **Генератор** (`core/vpngen/`) — получает бесплатный VPN-доступ у
  Cloudflare WARP или Proton VPN и выдаёт готовые конфиги для **AmneziaWG,
  usque (MASQUE), sing-box и mihomo**. Аналог сайтов warp-generation и
  proton-generation, но работает на роутере: ключи создаются локально,
  к API можно идти через уже работающий обход.
* **Мастер настройки** (`core/setup_wizard.py`) — «одна кнопка» для
  новичка: программа → установка → сервер → что пускать через VPN →
  запуск (конфиг + старт + автозапуск + маршрут единого слоя).

Сверено с клиентским кодом warp-generation.github.io и
proton-generation.github.io на **2026-10-15** (`docs/upstream.json`,
запись `warp-generation`) и с usque v4.2.1.

Перед правкой связанных частей читать и соседние скилы: `awg` (что умеет
ванильный WireGuard-пир), `masque-usque` (формат config.json, MTU 1280),
`singbox` (endpoints с 1.11, typed DNS), `mihomo` (amnezia-wg-option, masque).

---

## 1. Карта кода

| Файл | Что |
|---|---|
| `core/vpngen/keys.py` | X25519, Ed25519 (публичный из seed), P-256 + DER SEC1/SPKI. Чистый Python |
| `core/vpngen/net.py` | `request_json` через транспорт, `GenError(network=…)`, `run_with_transport` |
| `core/vpngen/presets.py` | DNS, адреса/порты Cloudflare, порты Proton, AllowedIPs, маски I1, junk |
| `core/vpngen/warp.py` | WARP: WireGuard и MASQUE, `native` и `service` |
| `core/vpngen/proton.py` | Proton: сессия (кеш 23 ч), серверы, сертификат |
| `core/vpngen/render.py` | профиль → .conf / config.json / sing-box JSON / mihomo YAML |
| `core/vpngen/generate.py` | оркестратор: опции → профиль → конфиги → `save_output` |
| `core/setup_wizard.py` | мастер: `options`, `devices`, установка, `apply(plan)` |
| `api/vpngen.py`, `api/setup_wizard.py` | REST |
| `core/mcp/tools/vpngen.py` | MCP |
| `web/js/pages/vpngen.js`, `setup_wizard.js`, `components/wizard.js` | UI |

## 2. Ключи (почему без зависимостей)

На роутере `python3-light` без `cryptography`, а `awg genkey`/`openssl`
могут отсутствовать (их ставят ради того самого туннеля). Поэтому:

* **X25519** (RFC 7748) — ключ WireGuard; публичный уходит в Cloudflare;
* **Ed25519** — только «публичный из seed» (RFC 8032 §5.1.5). Для Proton:
  WireGuard-ключ = первые 32 байта SHA-512(seed), «зажатые», то есть тот же
  скаляр. Сервису уходит **только** публичный Ed25519 в PEM (SPKI);
* **P-256** — ключ MASQUE. Формы как у Go: приватный —
  `x509.MarshalECPrivateKey` (SEC1, 121 байт, 164 символа base64 — поле
  `private_key` usque и mihomo), публичный — `MarshalPKIXPublicKey` (SPKI,
  91 байт, уходит в PATCH). Проверено реальными `sing-box check` 1.14.3 и
  `mihomo -t` 1.19.32.

Реализации не константны по времени — ключ создаётся один раз на своём же
устройстве, подписей нет. Сторож — `tests/test_vpngen_keys.py` (векторы
RFC 7748, RFC 8032, RFC 6979 A.2.5 + сверка с `cryptography`, если она есть).

## 3. WARP (`warp.py`)

API — **как у usque v4.2.1** (`internal/consts.go`): база
`https://api.cloudflareclient.com`, версия `v0a4471`, заголовки
`User-Agent: WARP for Android`, `CF-Client-Version: a-6.35-4471`.

**WireGuard:** `POST /v0a4471/reg` с телом
`{key: <X25519 pub>, install_id: "", fcm_token: "", tos, model: "PC",
serial_number: <8 случайных байт hex>, os_version: "", key_type: "curve25519",
tunnel_type: "wireguard", locale: "en_US"}`. Из ответа:
`config.peers[0].public_key`, `endpoint.host` (`engage.cloudflareclient.com:2408`),
`interface.addresses.v4/v6`, `config.client_id` → первые 3 байта = `reserved`
(sing-box/mihomo). Ответ бывает и плоским, и в `result` (`_unwrap`).
`endpoint.v4/v6` приходят с портом-плейсхолдером `:0` — не использовать как есть.

**MASQUE:** тот же `POST /reg`, но в `key` — **случайные 32 байта** (как
`GenerateRandomWgPubkey` у usque), затем `PATCH /reg/<id>` с
`Authorization: Bearer <token>` и `{key: <SPKI P-256>, key_type: "secp256r1",
tunnel_type: "masque", name?}`. В ответе `peers[0].public_key` — **PEM**
(usque хранит PEM, mihomo ждёт голый base64 SPKI → `keys.pem_body`),
`endpoint.v4` без `:0`. Профиль = поля config.json usque (`id`,
`access_token` из первой регистрации).

**WARP+:** `PUT /reg/<id>/account {license}` + `GET` — неудача становится
предупреждением, не ошибкой.

**source=service** — сервисы warp-generation (`SERVICE_WG`/`SERVICE_MASQUE`,
ответ `{privKey, peer_pub, client_ipv4, client_ipv6}`). Приватный ключ
создан чужим сервером — это пишется в `warnings` и в UI. У MASQUE из сервиса
нет учётки: `id`/`access_token` = `"service"` (туннелю usque они не нужны —
соединение аутентифицирует ключ; не сработают `usque account/enroll`).

**Сторонние ретрансляторы** WARP из чужих генераторов (серверы энтузиастов,
пересылающие UDP в Cloudflare) **не включены намеренно**: через них шёл бы
весь трафик пользователя. Пул адресов — только Cloudflare (`WARP_IP_PREFIXES`,
`WARP_PORTS`).

## 4. Proton (`proton.py`)

Анонимного API у Proton нет — WireGuard выдаётся под учётку. Используем
сервис proton-generation (`vpngen.proton_service`, по умолчанию
`https://www.api-proton.workers.dev`, только https://):

1. `POST /api/proton/session {}` → `{ok, session}` (кешируем 23 ч);
2. `POST /api/proton/servers {session}` → `servers[]`: `id, name,
   exitCountry, city, load, entryIp, publicKey`;
3. `POST /api/proton/certificate {session, clientPublicKey: <PEM Ed25519>,
   persistent: true}` — разрешает вход по нашему ключу.

Адреса в туннеле фиксированы: `10.2.0.2/32`, `2a07:b944::2:2/128`, DNS
`10.2.0.1`. Порты WireGuard: 51820, 443, 88, 80, 500, 1194, 1224, 4500,
4569, 5060. Успех — только явный `ok: true` (как в клиенте
proton-generation): ответ без него — ошибка, иначе вышел бы конфиг для
ключа, который Proton не авторизовал. `load` разбирается терпимо
(`"12.5"`, `"N/A"` → число/0). Ответ с ошибкой про token/session сбрасывает кеш.

**Сервис может быть закрыт для программ.** Владелец `api-proton.workers.dev`
включил в Cloudflare защиту по сигнатуре браузера: запрос не из браузера
получает 403 с `error_code: 1010` (`browser_signature_banned`) — и напрямую,
и через любой VPN. `net._cf_access_denied` распознаёт коды 1005–1012/1020 →
`GenError(blocked=True)`, не сетевая (у «Авто» нечего перебирать), API
отдаёт `blocked: true`. Подделывать браузерную сигнатуру **не делаем** —
это обход защиты, которую владелец поставил сознательно.

Запасной путь — **импорт** (`source="import"`, `proton.from_config`):
пользователь скачивает WireGuard-конфиг сам (account.protonvpn.com →
«Загрузки» → «Конфигурации WireGuard», бесплатный тариф тоже; или страница
proton-generation в браузере). Ключ в нём уже авторизован Proton; разбор —
`awg_config.parse_conf`, сервер и страна — из комментария `# NL-FREE#123`,
порт — из `Endpoint` (или явный `port`). Сети не нужно. В UI: шаг «Сервер»
генератора — «Мой конфиг Proton» (при `blocked` включается сам), в мастере
настройки — «Использовать свой конфиг Proton»; MCP — `source=import` +
`config`. **Формат
ответов взят из клиентского кода proton-generation, живьём не проверялся**
(доступа к сервису из среды разработки не было) — разбор терпим к
`camelCase`/`snake_case`.

## 5. Транспорт (`net.py`)

Спека — как у «Качать через» (`core/download_transport`): `direct`,
`awg:<iface>`, `singbox:<name>`, `mihomo:<name>`, плюс своё `auto`: напрямую,
затем все доступные обходы. **Следующий транспорт пробуется только после
сетевой ошибки** (`GenError.network=True`: таймаут, TLS, сброс, DNS); ответ
API (4xx/5xx, 429/1015) отдаётся сразу — через другой обход он не
исправится. Обход, которого уже нет (`build_opener` — RuntimeError: туннель
лёг, пока шли прежние попытки), и оборванный ответ
(`http.client.HTTPException`) — тоже сетевые ошибки. Повтор после таймаута —
только для GET/HEAD: POST `/reg` идёт один раз, иначе в Cloudflare остаются
лишние устройства. Результат сообщает, каким транспортом прошло (`transport`).

## 6. Обфускация и ванильный WireGuard

Cloudflare и Proton — **обычный WireGuard**. Совместимо только клиентское
(скил `awg` §2.1): `Jc/Jmin/Jmax` и `I1..I5`. `S1..S4=0`, `H1..H4=1..4`
пишутся явно, как только есть хоть какая-то обфускация; без неё (`junk=off`,
`mask=none`) конфиг — чистый WireGuard без AWG-полей. Маски I1:

* `quic` — настоящий QUIC Initial с ClientHello для SNI (шифрование
  Initial-ключами из `core/testers/quic_initial.py`), по умолчанию с PADDING
  до 1200 (RFC 9000 §14.1); SNI — случайный крупный российский сайт;
* `dns` — DNS-запрос A-записи; `sip` — INVITE + «100 Trying» (I1, I2);
* `custom` — теги `<b 0x…>`, `<r N>`, `<t>` как есть.

I1 длиннее 1400 байт отклоняется (фрагментация заметнее самого WG).
AWG 3 (`ContentPaddingAddition`, тайминги) — только в режиме эксперта;
`RandomTrailers` не предлагаем: он симметричный, сервер WARP его не знает.

## 7. Рендеры (`render.py`)

| Движок | WireGuard | MASQUE |
|---|---|---|
| AmneziaWG | `.conf` через `awg_config.render_conf` | — |
| usque | — | `config.json` (поля `config/config.go`; `endpoint_h2_v4=162.159.198.2`, `endpoint_h2_v6=""`) |
| sing-box | `endpoints[{type: wireguard}]` (в `outbounds` удалён в 1.13), `reserved`, `domain_resolver` для имени сервера | не умеет |
| mihomo | `type: wireguard` + `amnezia-wg-option` (`jc/jmin/jmax/i1..`, `version: 3` при AWG3) | `type: masque`, `public-key` — голый SPKI; два прокси H3/H2 в группе `fallback` |

Самостоятельные конфиги генератора: sing-box — mixed `127.0.0.1:<порт>` +
DNS через туннель (DoH 1.1.1.1, typed-формат 1.12+); mihomo — `mixed-port` на
localhost; имя группы — подпись без запятых (иначе ломается правило
`MATCH,<группа>`). Порты подбираются свободными (`pick_listen_port`: не заняты ни
сокетом, ни другим конфигом). MTU: WARP 1280, Proton 1420, MASQUE всегда 1280.

## 8. Оркестратор (`generate.py`)

* совместимость — `TARGETS` (WireGuard: awg/singbox/mihomo, MASQUE:
  usque/mihomo; usque — только WARP);
* одна регистрация на вызов → конфиги для всех выбранных движков; это
  **одно устройство** (один адрес в туннеле) — предупреждение «держите
  запущенным только один»;
* сохранение — менеджерами движков, **без перезаписи** (`save_output`
  отказывает на занятое имя, `unique_name` даёт `имя-2`). Проверка и запись —
под `_save_lock`; если список конфигов не прочитать, сохранение
отказывает (`strict`), а не пишет поверх; любая ошибка записи (OSError) —
ответ `{ok: false}`, не исключение. Ограничения имён:
  AWG ≤15, sing-box/mihomo ≤32, usque `[A-Za-z0-9_-]`;
* ответ содержит тексты с приватными ключами (их показывает страница) и
  служебный `secrets` — API его вырезает, MCP маскирует ключи (`mask`).

### Проверка синтаксиса (`check_output`)

`POST /api/vpngen/check {target, text}` и MCP `vpngen_check` (read): target —
движок или `proton-import`. Сначала встроенный разбор (`awg_config.validate`,
поля и IP usque `config.json`, `singbox_config.validate`, YAML mihomo с
`proxies`, `proton.from_config`), затем — если бинарь установлен —
`SingboxManager.check_text` / `MihomoManager.validate_via_binary(text=…)`;
их вердикт главнее. Нет бинаря — `warnings` «проверен только синтаксис».
Ответ `{ok, errors, checked_by, warnings, summary?}`; ничего не сохраняет.
UI: «Проверить» в карточке результата; у полей для готового конфига
(`Wizard.configInput`) — перетаскивание файла и автопроверка через 600 мс
после правки (ответ на устаревший текст отбрасывается по счётчику).
Автоматически забрать конфиг с сайта Proton нельзя (same-origin, у Proton
нет обратного вызова) — кнопка «Открыть аккаунт Proton ↗» +
перетаскивание.

## 9. MCP

| Инструмент | scope | Что |
|---|---|---|
| `vpngen_options` | read | возможности, пресеты, транспорты; без сети |
| `vpngen_check` | read | синтаксис конфига без сохранения (разбор + бинарь движка) |
| `vpngen_proton_servers` | tunnels_write, не мутирующий | серверы Proton (сеть к третьей стороне) |
| `vpngen_generate` | tunnels_write, мутирующий | генерирует и СОХРАНЯЕТ; ключи в ответе ««скрыто»»; снимок `generated_config` — откат удаляет созданное (если не запущено) |

## 10. Мастер настройки (`setup_wizard.py`)

`apply(plan)` → шаги `config` → `start` → `autostart` → `route`, стоп на
первом провале, отчёт в `steps`. Один запуск за раз (`_apply_lock`):
двойное нажатие не регистрирует второе устройство WARP. Маршрут, который
сохранился, но не применился в ядре (`applied.ok == false`), — провал шага
`route` с `partial: true` и `route_id`: туннель и маршрут уже есть, поэтому
UI вместо «Попробовать ещё раз» (дубли устройства WARP и маршрута) ведёт в
«Маршрутизацию → Диагностика»; текст ошибки — `apply_error()` (из
производных правил). Уже запущенный профиль usque («существующий») второй раз не
запускается. Автозапуск sing-box/mihomo проверяет результат `regenerate()`.

* **AWG/usque**: `generate` (через `vpngen.generate`, usque — всегда
  WARP MASQUE), `paste` (текст конфига), `existing`;
* **sing-box/mihomo**: `generate`, `link` (ссылки или URL подписки —
  скачивается через транспорт), `existing` (берутся прокси из конфига) —
  и собирается **новый** конфиг с TUN (`sbtun<N>`/`mhtun<N>`, sing-box: gvisor,
  `auto_route=false`, `172.19.N.1/30`; mihomo: `auto-route: false`). Несколько
  прокси → urltest/url-test, MASQUE → fallback. Проверка бинарём, если он
  установлен;
* **маршрут** — единый слой: метод `awg:<name>`, `warp:<iface usque>`,
  `singbox:<tun>`, `mihomo:<tun>`; сервисы → geosite/geoip (`SERVICES`),
  свои домены, именованные списки, устройства;
* **DNS-перехват** в TUN (`hijack-dns` / `dns-hijack: any:53`) включается
  только для «устройства»/«все». Он ловит DNS, отправленный внешним
  резолверам (8.8.8.8 и т.п.), — такой запрос уходит в TUN вместе с
  остальным трафиком устройства. DNS на адрес самого роутера доставляется
  локально и в TUN не попадает (его обслуживает DNS роутера);
* mihomo: локальные сети (10/8, 172.16/12, 192.168/16, 169.254/16) — `DIRECT`
  перед `MATCH,VPN`, повторяющиеся имена прокси нумеруются (`A (2)`);
  подписка в формате clash-YAML (`proxies:`) читается как есть;
* подписка по URL скачивается через `run_with_transport` («авто» —
  напрямую, при сетевой ошибке через обход; HTTP-ошибка — сразу);
* sing-box с TUN без `auto_route` видит только то, что ему отдало ядро:
  applier (`_singbox_sees_all`) тогда разворачивает geosite/geoip в наборы
  ядра, как для AWG, а не в правила движка;
* **«Все устройства» — поштучно, без адресов роутера и без соседей со
  стороны провайдера** (интерфейс маршрута по умолчанию; если он и есть
  мост LAN — точка доступа, роутер за роутером, — фильтр не применяется).
  Адрес роутера нельзя указать и вручную. Подсеть LAN в
  источнике захватила бы ответы самого роутера (его адрес в той же подсети):
  веб-интерфейс стал бы недоступен из LAN;
* автозапуск: sing-box/mihomo — `set_autostart`+`regenerate`, AWG —
  autostart-менеджер, usque — `usque.enabled`+`usque.autostart`.

UI: общий `Wizard` (шаги, «Назад/Далее», валидация шага); на страницах
движков — плашка «Настроить по шагам» (`Wizard.mountBanner`), ручные формы
маршрутизации sing-box/mihomo свёрнуты в блок «для опытных».

Тот же `Wizard` — в «Маршрутизации» (`routing_unified.js`: «Маршрут по
шагам» → `POST /api/unified/routes`; nfqws2/direct — только для сайтов,
geosite/geoip без туннеля игнорировались бы; устройства — только для
туннеля) и в «Оптимизациях» (`tunnel_optimizer.js`: профиль →
`POST /api/optimizer/optimize-all`, откат — `POST /api/optimizer/restore`). Экспертные
формы сохранены («+ Вручную», блок «Для опытных»).

`Wizard`: прокрутка к мастеру — только при смене шага (`rerender()` от
асинхронной подгрузки не дёргает страницу); `step.hideBack` прячет «Назад»
и блокирует переход по шапке на шаге-итоге после успешного применения.
Асинхронные подгрузки (серверы Proton, устройства) идут по одной и
перерисовывают шаг, только если пользователь всё ещё на нём.

## 11. Диагностика

| Симптом | Что смотреть |
|---|---|
| «TLS-соединение не устанавливается / таймаут» | Провайдер режет Cloudflare/сервис → «Авто» или конкретный обход (§5) |
| «слишком много запросов (HTTP 429)» / HTML вместо JSON | Ограничение частоты у Cloudflare (1015) или сервиса — подождать |
| «сессия Proton устарела» | Кеш сброшен — запросить серверы заново |
| «…не принимает запросы от программ (Cloudflare 1010)» | Сервис закрыт владельцем для не-браузеров; обход не поможет → «Мой конфиг Proton» (импорт, §4) |
| Туннель поднялся, трафика нет (AWG WARP) | S/H не ванильные (только если конфиг правили руками); endpoint/порт режут → «Случайный адрес Cloudflare» |
| sing-box не принял WireGuard | старый формат в `outbounds` — у нас `endpoints`; версия sing-box < 1.11 |
| mihomo: «failed to parse public key» (MASQUE) | в `public-key` PEM вместо голого SPKI |
| Мастер: «Интерфейс X уже существует» | Имя TUN занято — мастер берёт свободный `sbtunN`/`mhtunN`; см. скил `masque-usque` §7 для usque |
