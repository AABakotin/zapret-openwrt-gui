/**
 * vpngen.js — «Генератор конфигов»: WARP и Proton для AWG, usque,
 * sing-box и mihomo в пять шагов.
 *
 *   1. Сервис     — WARP (WireGuard/AmneziaWG), WARP MASQUE, Proton VPN
 *   2. Программы  — под какие движки собрать конфиг (только совместимые)
 *   3. Сервер     — только Proton: страна и сервер (по нагрузке)
 *   4. Настройки  — DNS, маскировка, «как выйти в сеть»; редкое — под
 *                   «Дополнительно»
 *   5. Готово     — конфиги: сохранить, скопировать, скачать, перейти к
 *                   движку или к мастеру маршрутизации
 *
 * Регистрация и сборка — на роутере (core/vpngen): ключи создаются
 * локально, наружу уходит только публичный ключ (кроме источника
 * «сервис-генератор», об этом сказано в интерфейсе).
 */
const VpnGenPage = (() => {
    const esc = Wizard.esc;
    let opts = null;
    let wizard = null;

    const SERVICES = [
        { id: 'warp-wg', provider: 'warp', protocol: 'wireguard',
          title: 'Cloudflare WARP',
          badge: 'WireGuard / AmneziaWG',
          desc: 'Бесплатный WARP. Работает в AmneziaWG, sing-box и mihomo.'
                + ' С маскировкой AmneziaWG проходит большинство блокировок.' },
        { id: 'warp-masque', provider: 'warp', protocol: 'masque',
          title: 'Cloudflare WARP',
          badge: 'MASQUE (HTTP/3)',
          desc: 'Тот же WARP, но выглядит как обычный HTTPS. Для usque и'
                + ' mihomo. Выручает, когда WireGuard режут по протоколу.' },
        { id: 'proton', provider: 'proton', protocol: 'wireguard',
          title: 'Proton VPN',
          badge: 'бесплатные серверы',
          desc: 'Серверы Proton в Нидерландах, Японии, США и др. Выбор'
                + ' страны. Для AmneziaWG, sing-box и mihomo.' },
    ];

    const TARGET_HELP = {
        awg: 'Туннель-интерфейс на роутере — можно завернуть в него сайты'
             + ' или устройства («Маршрутизация»).',
        usque: 'Клиент WARP по MASQUE: интерфейс usque0 для маршрутизации.',
        singbox: 'Прокси sing-box на роутере (обычный WireGuard, без'
                 + ' маскировки AmneziaWG).',
        mihomo: 'Прокси mihomo — с маскировкой AmneziaWG, а для MASQUE с'
                + ' автопереключением H3 ↔ H2.',
    };

    function initialState() {
        return {
            service: 'warp-wg', targets: [], serverId: '', country: '',
            servers: null, settings: {
                transport: 'auto', source: 'native', dns: '', mask: 'quic',
                mask_sni: '', junk: 'light', endpoint_mode: 'account',
                endpoint: '', ipv6: true, keepalive: 25, mtu: '',
                allowed: 'all', allowed_custom: '', license: '',
                device_name: '', sni: null, port: 51820, save: true,
                awg3: {},
            },
            // Proton: 'service' — сервис proton-generation, 'import' —
            // свой WireGuard-конфиг из аккаунта Proton.
            protonMode: 'service', protonConfig: '',
            result: null, needGenerate: true,
        };
    }

    function service(state) {
        return SERVICES.find(s => s.id === state.service) || SERVICES[0];
    }

    function compatible(state) {
        const svc = service(state);
        return (opts.targets || []).filter(t =>
            t.protocols.includes(svc.protocol)
            && !(t.id === 'usque' && svc.provider !== 'warp'));
    }

    // ───────────── шаг 1: сервис ─────────────

    function renderService(body, state, w) {
        body.innerHTML = `
            <p class="wizard-q">Какой VPN-сервис использовать?</p>
            <p class="wizard-sub">Оба бесплатные. Конфиг создаётся прямо на
               роутере — сторонние сайты не нужны.</p>
            <div class="choice-grid">
                ${SERVICES.map(s => `
                    <button class="choice-card ${state.service === s.id ? 'active' : ''}"
                            data-svc="${s.id}">
                        <div class="choice-title">${esc(s.title)}
                            <span class="badge badge-accent">${esc(s.badge)}</span></div>
                        <div class="choice-desc">${esc(s.desc)}</div>
                    </button>`).join('')}
            </div>`;
        body.querySelectorAll('[data-svc]').forEach(btn => {
            btn.addEventListener('click', () => {
                if (state.service !== btn.dataset.svc) {
                    state.service = btn.dataset.svc;
                    state.targets = [];
                    state.needGenerate = true;
                    state.settings.sni = null;
                    // Источник ключей и DNS зависят от сервиса: после Proton
                    // WARP не должен молча брать ключи у сервиса-генератора.
                    state.settings.source = 'native';
                    state.settings.dns = '';
                }
                w.rerender();
            });
        });
    }

    // ───────────── шаг 2: программы ─────────────

    function renderTargets(body, state, w) {
        const list = compatible(state);
        if (!state.targets.length) {
            // По умолчанию — то, что уже установлено (иначе первое).
            const inst = list.filter(t => t.installed).map(t => t.id);
            state.targets = inst.length ? [inst[0]] : (list[0] ? [list[0].id] : []);
        }
        body.innerHTML = `
            <p class="wizard-q">Для какой программы нужен конфиг?</p>
            <p class="wizard-sub">Можно выбрать несколько — регистрация будет
               одна. Не знаете, что выбрать, — берите то, что уже установлено.</p>
            <div class="choice-grid">
                ${list.map(t => `
                    <button class="choice-card ${state.targets.includes(t.id) ? 'active' : ''}"
                            data-target="${t.id}">
                        <div class="choice-title">${state.targets.includes(t.id) ? '☑' : '☐'}
                            ${esc(t.label)}
                            ${t.installed
                                ? '<span class="badge badge-success">установлен</span>'
                                : '<span class="badge badge-muted">не установлен</span>'}
                        </div>
                        <div class="choice-desc">${esc(TARGET_HELP[t.id] || '')}</div>
                    </button>`).join('')}
            </div>
            ${list.some(t => !t.installed && state.targets.includes(t.id)) ? `
                <div class="note-box warn">Программа не установлена — конфиг
                    сохранится, а запустить его можно будет после установки
                    (раздел программы → «Установка»).</div>` : ''}`;
        body.querySelectorAll('[data-target]').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.dataset.target;
                const i = state.targets.indexOf(id);
                if (i >= 0) state.targets.splice(i, 1);
                else state.targets.push(id);
                state.needGenerate = true;
                w.rerender();
            });
        });
    }

    // ───────────── шаг 3: сервер Proton ─────────────

    async function loadServers(state, w, refresh) {
        const box = document.getElementById('vg-servers');
        if (box) box.innerHTML = '<div class="text-muted">Загружаю список серверов…</div>';
        if (state.serversLoading) return;
        state.serversLoading = true;
        try {
            const r = await API.post('/api/vpngen/proton/servers',
                { transport: state.settings.transport, refresh: !!refresh },
                { timeout: 120000 });
            if (!r.ok) {
                state.servers = { error: r.error || 'ошибка', blocked: !!r.blocked };
                // Сервис закрыт владельцем для программ — повторы и обходы
                // бесполезны, сразу предлагаем свой конфиг.
                if (r.blocked) state.protonMode = 'import';
            } else {
                state.servers = r;
            }
        } catch (e) {
            state.servers = { error: String(e.message || e) };
        }
        state.serversLoading = false;
        // Перерисовываем, только если пользователь всё ещё на шаге сервера.
        if (wizard && wizard.index === 2) w.rerender();
    }

    const PROTON_HELP = `
        <ol class="wizard-sub" style="margin:6px 0 10px 18px; padding:0;">
            <li>Войдите в аккаунт Proton на <b>account.protonvpn.com</b> (бесплатный
                тариф подходит) → «Загрузки» → «Конфигурации WireGuard».</li>
            <li>Выберите платформу «Router» или «Linux», бесплатный сервер и нажмите
                «Создать» — скачается файл <code>.conf</code>.</li>
            <li>Перетащите файл на поле ниже, выберите его кнопкой или вставьте текст —
                проверка запустится сама.</li>
        </ol>
        <div class="gen-actions">
            <a class="btn btn-primary btn-sm" href="https://account.protonvpn.com/downloads"
               target="_blank" rel="noopener noreferrer">Открыть аккаунт Proton ↗</a>
            <a class="btn btn-ghost btn-sm" href="https://proton-generation.github.io/"
               target="_blank" rel="noopener noreferrer">proton-generation ↗</a>
        </div>
        <div class="form-hint">Подойдёт и конфиг со страницы proton-generation.github.io,
            открытой в браузере. Мы сохраним ключ из конфига и соберём из него
            AmneziaWG с маскировкой, sing-box и mihomo.</div>`;

    function renderServer(body, state, w) {
        const data = state.servers;
        const imp = state.protonMode === 'import';
        body.innerHTML = `
            <p class="wizard-q">Откуда взять сервер Proton?</p>
            <div class="choice-grid">
                <button class="choice-card ${imp ? '' : 'active'}" data-pmode="service">
                    <div class="choice-title">Выбрать в списке</div>
                    <div class="choice-desc">Список бесплатных серверов от сервиса
                        proton-generation. Ничего скачивать не нужно.</div>
                </button>
                <button class="choice-card ${imp ? 'active' : ''}" data-pmode="import">
                    <div class="choice-title">Мой конфиг Proton</div>
                    <div class="choice-desc">Файл WireGuard из аккаунта Proton. Работает,
                        даже если сервис недоступен.</div>
                </button>
            </div>
            <div id="vg-servers" style="margin-top:12px;"></div>`;
        body.querySelectorAll('[data-pmode]').forEach(b => b.onclick = () => {
            if (state.protonMode !== b.dataset.pmode) {
                state.protonMode = b.dataset.pmode;
                state.needGenerate = true;
            }
            w.rerender();
        });
        const box = body.querySelector('#vg-servers');
        if (imp) return renderProtonImport(box, state, data);
        if (!data) {
            box.innerHTML = '<div class="text-muted">Загружаю список серверов…</div>';
            loadServers(state, w, false);
            return;
        }
        renderServerList(box, state, w, data);
    }

    function renderProtonImport(box, state, data) {
        box.innerHTML = `
            ${data && data.blocked ? `<div class="note-box warn">Сервис proton-generation
                закрыт для программ (его владелец пускает только браузер), поэтому
                список серверов не получить ни напрямую, ни через VPN. Используйте
                свой конфиг Proton — это надёжнее.</div>` : ''}
            ${PROTON_HELP}
            <textarea class="form-input" id="vg-pconf" rows="9" spellcheck="false"
                style="width:100%; font-family:var(--font-mono); font-size:12px;"
                placeholder="[Interface]&#10;PrivateKey = …&#10;Address = 10.2.0.2/32&#10;&#10;[Peer]&#10;PublicKey = …&#10;Endpoint = …:51820">${esc(state.protonConfig)}</textarea>
            <div class="gen-actions">
                <label class="btn btn-ghost btn-sm" style="cursor:pointer;">Выбрать файл .conf
                    <input type="file" id="vg-pfile" accept=".conf,.txt,text/plain" style="display:none;">
                </label>
                <button class="btn btn-ghost btn-sm" id="vg-pcheck">Проверить конфиг</button>
            </div>
            <div id="vg-pcheck-out"></div>`;
        const ta = box.querySelector('#vg-pconf');
        const pcheck = box.querySelector('#vg-pcheck');
        const pout = box.querySelector('#vg-pcheck-out');
        ta.oninput = () => { state.protonConfig = ta.value; state.needGenerate = true; };
        // Вставили или перетащили файл — проверяем сразу, без лишней кнопки.
        Wizard.configInput(ta, t => {
            if (t.trim()) checkConfig('proton-import', t, pcheck, pout);
            else pout.innerHTML = '';
        });
        box.querySelector('#vg-pfile').onchange = (e) => {
            const f = e.target.files && e.target.files[0];
            if (!f) return;
            f.text().then(t => {
                ta.value = t;
                ta.dispatchEvent(new Event('input'));
            });
        };
        pcheck.onclick = () => checkConfig('proton-import', state.protonConfig, pcheck, pout);
        if ((state.protonConfig || '').trim()) {
            checkConfig('proton-import', state.protonConfig, pcheck, pout);
        }
    }

    function renderServerList(box, state, w, data) {
        if (!data) {
            box.innerHTML = '<div class="text-muted">Загружаю список серверов…</div>';
            loadServers(state, w, false);
            return;
        }
        if (data.error) {
            box.innerHTML = `
                <div class="note-box err">Не удалось получить серверы: ${esc(data.error)}</div>
                <div class="note-box">Не выходит? Выберите выше «Мой конфиг Proton» —
                    он работает без этого сервиса.</div>
                <div class="form-group" style="max-width:420px;">
                    <label class="form-label">Если сервис заблокирован — идти через</label>
                    <select class="form-input" id="vg-srv-transport">${options(opts.transports, state.settings.transport)}</select>
                </div>
                <button class="btn btn-primary btn-sm" data-vg="reload">Повторить</button>`;
            box.querySelector('#vg-srv-transport').onchange = (e) => {
                state.settings.transport = e.target.value;
            };
            box.querySelector('[data-vg="reload"]').onclick =
                () => loadServers(state, w, true);
            return;
        }
        const servers = data.servers || [];
        const countries = data.countries || [];
        const shown = servers.filter(s => !state.country || s.country === state.country);
        box.innerHTML = `
            <div class="gen-actions">
                <button class="btn btn-sm ${state.country ? 'btn-ghost' : 'btn-primary'}"
                        data-country="">🌍 Любая</button>
                ${countries.map(c => `
                    <button class="btn btn-sm ${state.country === c ? 'btn-primary' : 'btn-ghost'}"
                            data-country="${esc(c)}">${flag(c)} ${esc(c)}</button>`).join('')}
            </div>
            <select class="form-input" id="vg-server" style="max-width:520px;">
                <option value="">Наименее загруженный${state.country ? ' в ' + esc(state.country) : ''}</option>
                ${shown.slice().sort((a, b) => a.load - b.load).map(s => `
                    <option value="${esc(s.id)}" ${state.serverId === s.id ? 'selected' : ''}>
                        ${flag(s.country)} ${esc(s.name)} — ${esc(s.city)} · нагрузка ${s.load}%
                    </option>`).join('')}
            </select>
            <div class="gen-actions">
                <span class="text-muted" style="font-size:12px;">Серверов: ${servers.length}
                    ${data.transport && data.transport !== 'direct' ? ' · получено через ' + esc(data.transport) : ''}</span>
                <button class="btn btn-ghost btn-sm" data-vg="reload">Обновить список</button>
            </div>`;
        box.querySelectorAll('[data-country]').forEach(b => b.onclick = () => {
            state.country = b.dataset.country;
            state.serverId = '';
            state.needGenerate = true;
            w.rerender();
        });
        box.querySelector('#vg-server').onchange = (e) => {
            state.serverId = e.target.value;
            state.needGenerate = true;
        };
        box.querySelector('[data-vg="reload"]').onclick =
            () => loadServers(state, w, true);
    }

    function flag(cc) {
        if (!/^[A-Za-z]{2}$/.test(cc || '')) return '';
        return String.fromCodePoint(...cc.toUpperCase().split('')
            .map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
    }

    // ───────────── шаг 4: настройки ─────────────

    function options(list, current) {
        return (list || []).map(o =>
            `<option value="${esc(o.id)}" ${o.id === current ? 'selected' : ''}>${esc(o.label)}</option>`
        ).join('');
    }

    function renderSettings(body, state) {
        const svc = service(state);
        const s = state.settings;
        const wg = svc.protocol === 'wireguard';
        if (!s.dns) s.dns = svc.provider === 'proton' ? 'provider' : 'cloudflare';
        if (s.sni === null) s.sni = opts.default_sni || '';
        if (svc.provider === 'proton') {
            s.source = state.protonMode === 'import' ? 'import' : 'service';
        }
        // Свой конфиг Proton: сеть не нужна, порт — из конфига.
        const imp = svc.provider === 'proton' && state.protonMode === 'import';
        const dnsList = (opts.dns || []).filter(d =>
            d.id !== 'provider' || svc.provider === 'proton');

        body.innerHTML = `
            <p class="wizard-q">Последние настройки</p>
            <p class="wizard-sub">Подходящие значения уже выбраны — можно сразу
               жать «Сгенерировать».</p>
            <div class="settings-grid">
                ${imp ? '' : `<div class="form-group">
                    <label class="form-label">Как дойти до ${svc.provider === 'proton' ? 'сервиса Proton' : 'Cloudflare'}</label>
                    <select class="form-input" data-s="transport">${options(opts.transports, s.transport)}</select>
                    <div class="form-hint">«Авто»: сначала напрямую, а если провайдер
                        режет — через уже работающий AWG/sing-box/mihomo.</div>
                </div>`}
                ${wg ? `
                <div class="form-group">
                    <label class="form-label">Маскировка трафика</label>
                    <select class="form-input" data-s="mask">${options(opts.masks, s.mask)}</select>
                    <div class="form-hint">Перед подключением отправляется пакет,
                        похожий на другой протокол. Работает в AmneziaWG и mihomo.</div>
                </div>` : `
                <div class="form-group">
                    <label class="form-label">Маскировка под сайт (SNI)</label>
                    <input class="form-input" data-s="sni" value="${esc(s.sni)}" placeholder="ozon.ru">
                    <div class="form-hint">Для mihomo. usque берёт SNI из своих настроек.</div>
                </div>`}
                <div class="form-group">
                    <label class="form-label">DNS</label>
                    <select class="form-input" data-s="dns">${options(dnsList, s.dns)}</select>
                </div>
                <div class="form-group" data-show="dns=custom">
                    <label class="form-label">Свои DNS</label>
                    <input class="form-input" data-s="dns_custom" value="${esc(s.dns_custom || '')}"
                           placeholder="9.9.9.9, 149.112.112.112">
                </div>
                <div class="form-group">
                    <label class="form-label" style="display:flex;gap:8px;align-items:center;">
                        <input type="checkbox" data-s="save" ${s.save ? 'checked' : ''}>
                        Сразу сохранить конфиги</label>
                    <div class="form-hint">Можно снять и сохранить после просмотра.</div>
                </div>
            </div>
            <details style="margin-top:12px;">
                <summary style="cursor:pointer;">Дополнительно</summary>
                <div class="settings-grid" style="margin-top:12px;">
                    ${svc.provider === 'warp' ? `
                    <div class="form-group">
                        <label class="form-label">Откуда брать ключи</label>
                        <select class="form-input" data-s="source">
                            <option value="native" ${s.source === 'native' ? 'selected' : ''}>Напрямую в Cloudflare (ключ создаётся на роутере)</option>
                            <option value="service" ${s.source === 'service' ? 'selected' : ''}>Сервис-генератор warp-generation (ключ создаёт сервис)</option>
                        </select>
                        <div class="form-hint">Сервис — запасной путь, если до Cloudflare
                            не достучаться ни напрямую, ни через обход.</div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">WARP+ ключ (необязательно)</label>
                        <input class="form-input" data-s="license" value="${esc(s.license)}"
                               placeholder="xxxxxxxx-xxxxxxxx-xxxxxxxx">
                    </div>` : imp ? '' : `
                    <div class="form-group">
                        <label class="form-label">Порт сервера</label>
                        <select class="form-input" data-s="port">
                            ${(opts.proton_ports || []).map(p => `<option ${Number(s.port) === p ? 'selected' : ''}>${p}</option>`).join('')}
                        </select>
                        <div class="form-hint">Если 51820 режут — попробуйте 443 или 500.</div>
                    </div>`}
                    ${wg ? `
                    <div class="form-group">
                        <label class="form-label">Мусорные пакеты (junk)</label>
                        <select class="form-input" data-s="junk">${options(opts.junk, s.junk)}</select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Сайт для маски QUIC/DNS</label>
                        <input class="form-input" data-s="mask_sni" value="${esc(s.mask_sni)}"
                               placeholder="случайный: ${esc((opts.sni_domains || [])[0] || 'ozon.ru')}…">
                    </div>
                    <div class="form-group" data-show="mask=custom">
                        <label class="form-label">Свой I1</label>
                        <input class="form-input" data-s="mask_custom" value="${esc(s.mask_custom || '')}"
                               placeholder="<b 0x…> или <r 64>">
                    </div>
                    ${svc.provider === 'warp' ? `
                    <div class="form-group">
                        <label class="form-label">Адрес сервера WARP</label>
                        <select class="form-input" data-s="endpoint_mode">${options(opts.endpoint_modes, s.endpoint_mode)}</select>
                    </div>
                    <div class="form-group" data-show="endpoint_mode=custom">
                        <label class="form-label">Свой адрес:порт</label>
                        <input class="form-input" data-s="endpoint" value="${esc(s.endpoint)}"
                               placeholder="162.159.192.1:2408">
                    </div>` : ''}
                    <div class="form-group">
                        <label class="form-label">Какой трафик пускать в туннель</label>
                        <select class="form-input" data-s="allowed">${options(opts.allowed, s.allowed)}</select>
                    </div>
                    <div class="form-group" data-show="allowed=custom">
                        <label class="form-label">Подсети через запятую</label>
                        <input class="form-input" data-s="allowed_custom" value="${esc(s.allowed_custom)}"
                               placeholder="8.8.8.0/24, 1.1.1.1/32">
                    </div>
                    <div class="form-group">
                        <label class="form-label">MTU</label>
                        <input class="form-input" type="number" min="1200" max="1500" data-s="mtu"
                               value="${esc(s.mtu)}" placeholder="${svc.provider === 'proton' ? 1420 : 1280}">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Keepalive, с</label>
                        <input class="form-input" type="number" min="0" max="600" data-s="keepalive"
                               value="${esc(s.keepalive)}">
                    </div>` : `
                    <div class="form-group">
                        <label class="form-label">Имя устройства в Cloudflare</label>
                        <input class="form-input" data-s="device_name" value="${esc(s.device_name)}"
                               placeholder="router">
                    </div>`}
                    <div class="form-group">
                        <label class="form-label" style="display:flex;gap:8px;align-items:center;">
                            <input type="checkbox" data-s="ipv6" ${s.ipv6 ? 'checked' : ''}>
                            IPv6 внутри туннеля</label>
                    </div>
                    ${wg ? `
                    <div class="form-group expert-only">
                        <label class="form-label">AWG 3: ContentPaddingAddition</label>
                        <input class="form-input" data-awg3="ContentPaddingAddition"
                               value="${esc(s.awg3.ContentPaddingAddition || '')}" placeholder="не задано">
                        <div class="form-hint">Только для AmneziaWG/mihomo v3+.</div>
                    </div>` : ''}
                </div>
            </details>`;

        const sync = () => {
            body.querySelectorAll('[data-show]').forEach(el => {
                const [k, v] = el.dataset.show.split('=');
                el.style.display = String(s[k]) === v ? '' : 'none';
            });
        };
        body.querySelectorAll('[data-s]').forEach(el => {
            const key = el.dataset.s;
            const handler = () => {
                s[key] = el.type === 'checkbox' ? el.checked : el.value;
                if (key !== 'save') state.needGenerate = true;
                if (key === 'transport') state.servers = null;
                sync();
            };
            el.addEventListener('change', handler);
            el.addEventListener('input', handler);
        });
        body.querySelectorAll('[data-awg3]').forEach(el => {
            el.addEventListener('input', () => {
                s.awg3[el.dataset.awg3] = el.value.trim();
                state.needGenerate = true;
            });
        });
        sync();
    }

    // ───────────── шаг 5: результат ─────────────

    function request(state) {
        const svc = service(state);
        const s = state.settings;
        const o = {
            dns: s.dns, dns_custom: s.dns_custom || '', ipv6: !!s.ipv6, allowed: s.allowed,
            allowed_custom: s.allowed_custom, keepalive: s.keepalive,
        };
        if (s.mtu) o.mtu = s.mtu;
        if (svc.protocol === 'masque') {
            o.sni = s.sni;
        } else {
            Object.assign(o, {
                mask: s.mask, mask_sni: s.mask_sni, mask_custom: s.mask_custom || '',
                junk: s.junk, endpoint_mode: s.endpoint_mode,
                endpoint: s.endpoint, awg3: s.awg3,
            });
        }
        return {
            provider: svc.provider, protocol: svc.protocol,
            source: s.source, transport: s.transport,
            targets: state.targets, save: !!s.save, options: o,
            license: s.license, device_name: s.device_name,
            server_id: state.serverId, country: state.country,
            port: s.source === 'import' ? '' : s.port,
            config: s.source === 'import' ? state.protonConfig : undefined,
        };
    }

    async function generate(state, w, body) {
        body.innerHTML = `<div class="note-box">Регистрирую устройство и собираю
            конфиги… Обычно это 5–20 секунд, через обход — дольше.</div>`;
        w.setBusy(true);
        try {
            const r = await API.post('/api/vpngen/generate', request(state),
                                     { timeout: 240000 });
            state.result = r;
            state.needGenerate = !r.ok && !r.results;
        } catch (e) {
            state.result = { ok: false, error: String(e.message || e) };
        } finally {
            w.setBusy(false);
        }
        renderResult(body, state, w);
    }

    function renderResult(body, state, w) {
        if (state.needGenerate || !state.result) {
            generate(state, w, body);
            return;
        }
        const r = state.result;
        if (r.error && !r.results) {
            body.innerHTML = `
                <div class="note-box err">${esc(r.error)}</div>
                <p class="wizard-sub">Чаще всего это блокировка: вернитесь на шаг
                   «Настройки» и выберите выход через обход (или «Авто»).</p>
                <button class="btn btn-primary" data-vg="again">Попробовать ещё раз</button>`;
            body.querySelector('[data-vg="again"]').onclick = () => {
                state.needGenerate = true;
                renderResult(body, state, w);
            };
            return;
        }
        const acc = r.account || {};
        const srv = r.server;
        body.innerHTML = `
            <div class="note-box ok">Готово${r.transport && r.transport !== 'direct'
                ? ' (через ' + esc(r.transport) + ')' : ''}.
                ${srv && srv.name ? 'Сервер: ' + esc([srv.name, srv.city].filter(Boolean).join(', ')) + '.' : ''}
                ${acc.warp_plus ? ' Аккаунт WARP+.' : ''}</div>
            ${(r.warnings || []).map(x => `<div class="note-box warn">${esc(x)}</div>`).join('')}
            <div id="vg-results"></div>
            <div class="gen-actions" style="margin-top:12px;">
                <button class="btn btn-ghost" data-vg="again">Сгенерировать заново</button>
                <button class="btn btn-ghost" data-vg="new">Новый конфиг</button>
            </div>`;
        const box = body.querySelector('#vg-results');
        Object.values(r.results || {}).forEach(item => box.appendChild(resultCard(item)));
        body.querySelector('[data-vg="again"]').onclick = () => {
            state.needGenerate = true;
            renderResult(body, state, w);
        };
        body.querySelector('[data-vg="new"]').onclick = () => {
            render(document.getElementById('vg-root').parentElement);
        };
    }

    const ENGINE_PAGE = { awg: 'awg-configs', usque: 'usque',
                          singbox: 'singbox-configs', mihomo: 'mihomo' };

    // Проверка синтаксиса без сохранения: /api/vpngen/check.
    async function checkConfig(target, text, btn, out) {
        if (btn) btn.disabled = true;
        // Автопроверка идёт на каждую правку: ответ на устаревший текст,
        // пришедший позже свежего, не должен его перезаписать.
        const seq = out._seq = (out._seq || 0) + 1;
        out.innerHTML = '<div class="text-muted" style="font-size:12px;">Проверяю…</div>';
        try {
            const r = await API.post('/api/vpngen/check', { target, text },
                                     { timeout: 30000 });
            if (out._seq !== seq) return;
            out.innerHTML = checkResultHtml(r);
        } catch (e) {
            if (out._seq !== seq) return;
            out.innerHTML = `<div class="note-box err">Проверка не выполнена: ${esc(e.message || e)}</div>`;
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    function checkResultHtml(r) {
        const by = (r.checked_by || []).join(' + ');
        const head = r.ok
            ? `✅ Синтаксис в порядке${r.summary ? ': ' + esc(r.summary) : ''}`
            : '❌ Ошибки в конфиге:';
        return `<div class="note-box ${r.ok ? 'ok' : 'err'}">${head}
            ${r.ok ? '' : `<ul style="margin:4px 0 0 18px; padding:0;">${(r.errors || [])
                .map(x => `<li>${esc(x)}</li>`).join('')}</ul>`}
            ${by ? `<div class="form-hint" style="margin-top:4px;">Проверено: ${esc(by)}</div>` : ''}
            ${(r.warnings || []).map(x => `<div class="form-hint">⚠ ${esc(x)}</div>`).join('')}
        </div>`;
    }

    function resultCard(item) {
        const card = document.createElement('div');
        card.className = 'card gen-result';
        const routable = item.target === 'singbox' || item.target === 'mihomo';
        card.innerHTML = `
            <div class="card-title">${esc(item.label)}
                ${item.saved ? '<span class="badge badge-success">сохранён</span>' : ''}</div>
            ${item.error ? `<div class="note-box err">${esc(item.error)}</div>` : ''}
            <div class="gen-actions">
                <input class="form-input" data-r="name" value="${esc(item.name)}"
                       style="max-width:240px;" ${item.saved ? 'disabled' : ''}>
                ${item.saved ? '' : '<button class="btn btn-primary btn-sm" data-r="save">Сохранить</button>'}
                <button class="btn btn-ghost btn-sm" data-r="check"
                        title="Проверить синтаксис: встроенный разбор, а если программа установлена — она сама">Проверить</button>
                <button class="btn btn-ghost btn-sm" data-r="copy">Скопировать</button>
                <button class="btn btn-ghost btn-sm" data-r="download">Скачать</button>
                <a class="btn btn-ghost btn-sm" data-r="open" href="#${ENGINE_PAGE[item.target]}"
                   style="${item.saved ? '' : 'display:none;'}">Открыть ${esc(item.label)} →</a>
                ${routable ? `<a class="btn btn-ghost btn-sm" data-r="route"
                   href="#setup-wizard?engine=${item.target}&config=${encodeURIComponent(item.name)}"
                   style="${item.saved ? '' : 'display:none;'}">Настроить маршрутизацию →</a>` : ''}
            </div>
            <div data-r="check-out"></div>
            ${item.listen_port ? `<div class="form-hint">Локальный прокси:
                127.0.0.1:${item.listen_port} (HTTP и SOCKS5).</div>` : ''}
            <details><summary style="cursor:pointer;">Показать конфиг</summary>
                <textarea readonly spellcheck="false">${esc(item.text)}</textarea>
            </details>`;
        const nameEl = card.querySelector('[data-r="name"]');
        const saveBtn = card.querySelector('[data-r="save"]');
        if (saveBtn) saveBtn.onclick = async () => {
            saveBtn.disabled = true;
            try {
                const res = await API.post('/api/vpngen/save', {
                    target: item.target, name: nameEl.value.trim(), text: item.text });
                if (!res.ok) throw new Error(res.error || 'не сохранено');
                item.saved = true;
                item.name = res.name;
                item.error = '';
                Toast.success('Сохранено: ' + res.name);
                card.replaceWith(resultCard(item));
            } catch (e) {
                Toast.error(String(e.message || e));
                saveBtn.disabled = false;
            }
        };
        const checkBtn = card.querySelector('[data-r="check"]');
        checkBtn.onclick = () => checkConfig(item.target, item.text, checkBtn,
                                             card.querySelector('[data-r="check-out"]'));
        card.querySelector('[data-r="copy"]').onclick = async () => {
            try {
                await Clipboard.copy(item.text);
                Toast.success('Скопировано');
            } catch (e) { Toast.error('Не удалось скопировать'); }
        };
        card.querySelector('[data-r="download"]').onclick = () => {
            const ext = { conf: '.conf', json: '.json', yaml: '.yaml' }[item.format] || '.txt';
            const a = document.createElement('a');
            a.href = URL.createObjectURL(new Blob([item.text], { type: 'text/plain' }));
            a.download = (nameEl.value.trim() || item.name) + ext;
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(a.href), 1000);
        };
        return card;
    }

    // ───────────── страница ─────────────

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">Генератор конфигов</h1>
                <p class="text-muted" style="margin:4px 0 0 0;">
                    WARP и Proton VPN для AmneziaWG, WARP/MASQUE, sing-box и mihomo —
                    за пару шагов, без сторонних сайтов.</p>
            </div>
            <div class="card" id="vg-root"><div class="text-muted">Загрузка…</div></div>`;
        const root = container.querySelector('#vg-root');
        try {
            opts = await API.get('/api/vpngen/options');
        } catch (e) {
            root.innerHTML = `<div class="note-box err">Не удалось загрузить
                параметры: ${esc(e.message || e)}</div>`;
            return;
        }
        const params = new URLSearchParams((location.hash.split('?')[1]) || '');
        const state = initialState();
        if (params.get('service') && SERVICES.some(s => s.id === params.get('service'))) {
            state.service = params.get('service');
        }
        // Программа из ссылки — только совместимая с сервисом (MASQUE не
        // ставится в AmneziaWG и т.п.), иначе выберется по умолчанию.
        if (params.get('target')
            && compatible(state).some(t => t.id === params.get('target'))) {
            state.targets = [params.get('target')];
        }

        wizard = Wizard.create(root, {
            state,
            steps: [
                { id: 'service', title: 'Сервис', render: renderService },
                { id: 'targets', title: 'Программа', render: renderTargets,
                  validate: s => s.targets.length ? '' : 'Отметьте хотя бы одну программу' },
                { id: 'server', title: 'Сервер', render: renderServer,
                  skip: s => service(s).provider !== 'proton',
                  validate: s => s.protonMode === 'import'
                      ? (/\[Peer\]/i.test(s.protonConfig || '') && /PrivateKey/i.test(s.protonConfig || '')
                          ? '' : 'Вставьте WireGuard-конфиг Proton целиком: [Interface] и [Peer]')
                      : ((s.servers && s.servers.servers && s.servers.servers.length)
                          ? '' : 'Список серверов ещё не получен — или выберите «Мой конфиг Proton»') },
                { id: 'settings', title: 'Настройки', render: renderSettings,
                  nextLabel: 'Сгенерировать' },
                { id: 'result', title: 'Готово', render: renderResult,
                  hideNext: true },
            ],
        });
        wizard.go(0);
    }

    function destroy() { wizard = null; }

    return { render, destroy };
})();
