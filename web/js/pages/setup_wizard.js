/**
 * setup_wizard.js — «Мастер настройки»: VPN за пять простых шагов.
 *
 *   1. Программа   — AmneziaWG, WARP/MASQUE (usque), sing-box, mihomo
 *   2. Установка   — поставить программу, если её ещё нет
 *   3. Сервер      — бесплатный WARP/Proton, ссылка/подписка, готовый
 *                    конфиг или тот, что уже есть
 *   4. Что пускать — нужные сайты, устройства, всё или ничего
 *   5. Запуск      — сохранить, запустить, включить автозапуск и
 *                    маршрутизацию одной кнопкой (POST /api/setup-wizard/apply)
 *
 * Тексты — для человека без опыта: что выбрать и зачем, без терминов,
 * где их можно избежать. Всё «продвинутое» остаётся на страницах движков.
 */
const SetupWizardPage = (() => {
    const esc = Wizard.esc;
    let opts = null;
    let wizard = null;
    let pollTimer = null;
    // Поколение страницы: ответ опроса, пришедший после ухода со страницы
    // (или после смены программы), не должен запускать новый опрос.
    let pollGen = 0;

    const ENGINE_INFO = {
        awg: { title: 'AmneziaWG', badge: 'рекомендуем',
               desc: 'Самый быстрый. VPN-туннель с маскировкой от блокировок.'
                     + ' Подходит для бесплатного WARP и Proton.' },
        usque: { title: 'WARP/MASQUE', badge: 'если WireGuard режут',
                 desc: 'Бесплатный Cloudflare WARP, который выглядит как'
                       + ' обычный HTTPS. Работает там, где не работает остальное.' },
        singbox: { title: 'sing-box', badge: 'для своих серверов',
                   desc: 'Если у вас есть ссылка vless://, trojan://, ss:// или'
                         + ' подписка от VPN-сервиса. Также умеет WARP и Proton.' },
        mihomo: { title: 'mihomo', badge: 'для своих серверов',
                  desc: 'То же, что sing-box (ссылки и подписки), плюс WARP с'
                        + ' маскировкой и WARP MASQUE.' },
    };

    const SOURCES = {
        warp: { title: 'Бесплатный Cloudflare WARP',
                desc: 'Ничего не нужно: устройство зарегистрируется само.' },
        'warp-masque': { title: 'Бесплатный WARP (MASQUE)',
                         desc: 'WARP под видом HTTPS — если обычный режут.' },
        proton: { title: 'Бесплатный Proton VPN',
                  desc: 'Серверы в Европе, США, Японии. Выбор страны.' },
        link: { title: 'Ссылка или подписка',
                desc: 'vless://, vmess://, trojan://, ss://, hysteria2:// или'
                      + ' адрес подписки https://…' },
        paste: { title: 'Готовый конфиг',
                 desc: 'Вставьте текст файла (.conf или .json), который вам дали.' },
        existing: { title: 'Конфиг, который уже есть',
                    desc: 'Выбрать из сохранённых в программе.' },
    };

    function engine(state) {
        return (opts.engines || []).find(e => e.id === state.engine);
    }

    // Источники для движка в порядке «самое простое — первым».
    function sourcesFor(state) {
        const e = engine(state);
        if (!e) return [];
        const out = [];
        if (e.sources.includes('generate')) {
            if (e.id === 'usque') out.push('warp-masque');
            else {
                out.push('warp');
                if (e.id === 'mihomo') out.push('warp-masque');
                out.push('proton');
            }
        }
        if (e.sources.includes('link')) out.push('link');
        if (e.sources.includes('paste')) out.push('paste');
        if (e.sources.includes('existing') && e.configs.length) out.push('existing');
        return out;
    }

    // ─────────── шаг 1: программа ───────────

    function renderEngine(body, state, w) {
        body.innerHTML = `
            <p class="wizard-q">Что будем настраивать?</p>
            <p class="wizard-sub">Не знаете — выбирайте AmneziaWG: он быстрый и
               сам получит бесплатный сервер.</p>
            <div class="choice-grid">
                ${(opts.engines || []).map(e => {
                    const info = ENGINE_INFO[e.id] || {};
                    return `
                    <button class="choice-card ${state.engine === e.id ? 'active' : ''}"
                            data-engine="${esc(e.id)}">
                        <div class="choice-title">${esc(info.title || e.label)}
                            ${info.badge ? `<span class="badge badge-accent">${esc(info.badge)}</span>` : ''}
                            ${e.installed ? '<span class="badge badge-success">установлен</span>' : ''}
                        </div>
                        <div class="choice-desc">${esc(info.desc || '')}</div>
                    </button>`;
                }).join('')}
            </div>
            ${opts.platform && !opts.platform.tun_available ? `
                <div class="note-box warn">На роутере не включён TUN — без него
                    VPN-программы не запустятся. ${esc(opts.platform.tun_instructions || '')}</div>` : ''}`;
        body.querySelectorAll('[data-engine]').forEach(b => b.onclick = () => {
            if (state.engine !== b.dataset.engine) {
                state.engine = b.dataset.engine;
                state.source = '';
                state.install = null;
                pollGen++;
                clearTimeout(pollTimer);
                pollTimer = null;
            }
            w.rerender();
        });
    }

    // ─────────── шаг 2: установка ───────────

    function renderInstall(body, state, w) {
        const e = engine(state);
        const info = ENGINE_INFO[e.id] || {};
        if (e.installed) {
            body.innerHTML = `
                <p class="wizard-q">${esc(info.title)} уже установлен</p>
                <div class="note-box ok">Всё готово — жмите «Далее».</div>`;
            return;
        }
        const st = state.install || {};
        body.innerHTML = `
            <p class="wizard-q">Установим ${esc(info.title)}</p>
            <p class="wizard-sub">Программа скачается с GitHub (около 5–20 МБ) и
               поставится сама. Это займёт до пары минут.</p>
            ${st.running ? `<div class="note-box">⏳ ${esc(st.message || 'Устанавливаю…')}</div>` : ''}
            ${st.result === false ? `<div class="note-box err">Не получилось: ${esc(st.message || '')}.
                Если GitHub недоступен, выберите ниже «через …» и повторите.</div>` : ''}
            <div class="settings-grid">
                <div class="form-group">
                    <label class="form-label">Скачивать</label>
                    <select class="form-input" id="sw-inst-transport">
                        ${transportOptions(state.transport, true)}
                    </select>
                </div>
            </div>
            <button class="btn btn-primary" id="sw-install" ${st.running ? 'disabled' : ''}>
                ${st.running ? 'Устанавливаю…' : 'Установить'}</button>`;
        body.querySelector('#sw-inst-transport').onchange = (ev) => {
            state.transport = ev.target.value;
        };
        body.querySelector('#sw-install').onclick = async () => {
            try {
                const r = await API.post('/api/setup-wizard/install',
                    { engine: e.id, transport: state.transport });
                if (!r.ok) throw new Error(r.error || 'ошибка');
                state.install = { running: true, message: 'Скачиваю…' };
                w.rerender();
                poll(state, w);
            } catch (err) {
                Toast.error(String(err.message || err));
            }
        };
        if (st.running && !pollTimer) poll(state, w);
    }

    function poll(state, w, failures) {
        clearTimeout(pollTimer);
        const gen = pollGen;
        failures = failures || 0;
        pollTimer = setTimeout(async () => {
            pollTimer = null;
            try {
                const r = await API.get('/api/setup-wizard/install/status?engine='
                                        + encodeURIComponent(state.engine));
                if (gen !== pollGen) return;
                state.install = r;
                if (r.installed) {
                    engine(state).installed = true;
                    Toast.success('Установлено');
                } else if (!r.running && r.result === true) {
                    // Установщик отчитался «ок», а программа не находится —
                    // показываем это, а не молча оставляем кнопку.
                    state.install = { result: false,
                        message: r.message || 'установка завершилась, но программа не найдена' };
                }
                if (wizard && wizard.index === 1) w.rerender();
                if (r.running) poll(state, w);
            } catch (e) {
                if (gen !== pollGen) return;
                // Сервер не отвечает — несколько попыток, затем честная ошибка.
                if (failures < 5) { poll(state, w, failures + 1); return; }
                state.install = { result: false,
                    message: 'нет ответа от роутера: ' + String(e.message || e) };
                if (wizard && wizard.index === 1) w.rerender();
            }
        }, 2000);
    }

    function transportOptions(current, withAuto) {
        return (opts.transports || [])
            .filter(t => withAuto || t.id !== 'auto')
            .map(t => `<option value="${esc(t.id)}" ${t.id === current ? 'selected' : ''}>${esc(t.label)}</option>`)
            .join('');
    }

    // ─────────── шаг 3: сервер ───────────

    function renderSource(body, state, w) {
        const list = sourcesFor(state);
        if (!state.source || !list.includes(state.source)) state.source = list[0] || '';
        body.innerHTML = `
            <p class="wizard-q">Где взять VPN-сервер?</p>
            <p class="wizard-sub">Нет своего сервера — берите бесплатный вариант,
               он первый в списке.</p>
            <div class="choice-grid">
                ${list.map(id => `
                    <button class="choice-card ${state.source === id ? 'active' : ''}" data-src="${id}">
                        <div class="choice-title">${esc(SOURCES[id].title)}</div>
                        <div class="choice-desc">${esc(SOURCES[id].desc)}</div>
                    </button>`).join('')}
            </div>
            <div id="sw-src-detail" style="margin-top:14px;"></div>`;
        body.querySelectorAll('[data-src]').forEach(b => b.onclick = () => {
            state.source = b.dataset.src;
            w.rerender();
        });
        const box = body.querySelector('#sw-src-detail');
        const src = state.source;
        if (src === 'proton') renderProton(box, state, w);
        else if (src === 'link') {
            box.innerHTML = `
                <label class="form-label">Ссылка, несколько ссылок (по одной в строке)
                    или адрес подписки</label>
                <textarea class="form-input" id="sw-link" rows="4" spellcheck="false"
                          style="font-family:var(--font-mono);font-size:12px;"
                          placeholder="vless://…&#10;https://подписка.example/sub">${esc(state.link || '')}</textarea>
                <div class="form-hint">Из нескольких серверов программа сама выберет
                    самый быстрый.</div>`;
            box.querySelector('#sw-link').oninput = (ev) => { state.link = ev.target.value; };
        } else if (src === 'paste') {
            box.innerHTML = `
                <label class="form-label">Текст конфига</label>
                <textarea class="form-input" id="sw-paste" rows="10" spellcheck="false"
                          style="font-family:var(--font-mono);font-size:12px;"
                          placeholder="${state.engine === 'usque' ? '{ &quot;private_key&quot;: …' : '[Interface]&#10;PrivateKey = …'}">${esc(state.paste || '')}</textarea>
                <div class="gen-actions">
                    <input type="file" id="sw-file" accept=".conf,.json,.txt" style="display:none;">
                    <button class="btn btn-ghost btn-sm" id="sw-file-btn">Загрузить файл</button>
                </div>`;
            box.querySelector('#sw-paste').oninput = (ev) => { state.paste = ev.target.value; };
            const file = box.querySelector('#sw-file');
            box.querySelector('#sw-file-btn').onclick = () => file.click();
            file.onchange = () => {
                const f = file.files && file.files[0];
                if (!f) return;
                f.text().then(t => { state.paste = t; w.rerender(); });
            };
        } else if (src === 'existing') {
            const configs = engine(state).configs || [];
            if (!state.existing || !configs.includes(state.existing)) state.existing = configs[0] || '';
            box.innerHTML = `
                <label class="form-label">Конфиг</label>
                <select class="form-input" id="sw-existing" style="max-width:320px;">
                    ${configs.map(c => `<option ${c === state.existing ? 'selected' : ''}>${esc(c)}</option>`).join('')}
                </select>
                ${['singbox', 'mihomo'].includes(state.engine) ? `
                    <div class="form-hint">Мастер возьмёт из него серверы и соберёт
                        новый конфиг с интерфейсом для маршрутизации — старый
                        не изменится.</div>` : ''}`;
            box.querySelector('#sw-existing').onchange = (ev) => { state.existing = ev.target.value; };
        } else if (src === 'warp' && ['awg', 'mihomo'].includes(state.engine)) {
            box.innerHTML = `<div class="note-box">Включим маскировку под обычный
                QUIC-трафик (AmneziaWG) — так WARP проходит большинство блокировок.</div>`;
        }
    }

    async function renderProton(box, state, w) {
        const data = state.proton;
        if (!data) {
            box.innerHTML = '<div class="text-muted">Загружаю список серверов Proton…</div>';
            // Один запрос за раз: клики Proton → WARP → Proton во время
            // загрузки не плодят параллельные запросы.
            if (state.protonLoading) return;
            state.protonLoading = true;
            try {
                const r = await API.post('/api/vpngen/proton/servers',
                    { transport: state.transport }, { timeout: 120000 });
                state.proton = r.ok ? r : { error: r.error || 'ошибка' };
            } catch (e) {
                state.proton = { error: String(e.message || e) };
            }
            state.protonLoading = false;
            // Пользователь мог уже уйти на «Ссылку» и печатать — не
            // перерисовываем (поле потеряло бы фокус).
            if (wizard && wizard.index === 2 && state.source === 'proton') w.rerender();
            return;
        }
        if (data.error) {
            box.innerHTML = `<div class="note-box err">Серверы Proton не загрузились:
                    ${esc(data.error)}</div>
                <div class="form-group" style="max-width:420px;">
                    <label class="form-label">Попробовать через</label>
                    <select class="form-input" id="sw-px-tr">${transportOptions(state.transport, true)}</select>
                </div>
                <button class="btn btn-ghost btn-sm" id="sw-px-retry">Повторить</button>`;
            box.querySelector('#sw-px-tr').onchange = (ev) => { state.transport = ev.target.value; };
            box.querySelector('#sw-px-retry').onclick = () => { state.proton = null; w.rerender(); };
            return;
        }
        const countries = data.countries || [];
        box.innerHTML = `
            <label class="form-label">Страна сервера</label>
            <select class="form-input" id="sw-country" style="max-width:320px;">
                <option value="">Любая (наименее загруженная)</option>
                ${countries.map(c => `<option value="${esc(c)}" ${state.country === c ? 'selected' : ''}>${esc(c)}</option>`).join('')}
            </select>`;
        box.querySelector('#sw-country').onchange = (ev) => { state.country = ev.target.value; };
    }

    function validateSource(state) {
        const s = state.source;
        if (!s) return 'Выберите, откуда взять сервер';
        if (s === 'link' && !(state.link || '').trim()) return 'Вставьте ссылку или подписку';
        if (s === 'paste' && !(state.paste || '').trim()) return 'Вставьте текст конфига';
        if (s === 'proton' && !(state.proton && state.proton.servers)) return 'Серверы Proton ещё не загружены';
        if (s === 'existing' && !state.existing) return 'Выберите конфиг';
        return '';
    }

    // ─────────── шаг 4: что пускать ───────────

    const MODES = [
        { id: 'sites', title: 'Только нужные сайты', badge: 'рекомендуем',
          desc: 'YouTube, Telegram, ChatGPT и т. п. пойдут через VPN, остальное —'
                + ' как обычно. Быстро и без лишних проблем.' },
        { id: 'devices', title: 'Всё с выбранных устройств',
          desc: 'Например, весь интернет телевизора или телефона — через VPN.' },
        { id: 'all', title: 'Весь интернет со всех устройств',
          desc: 'Все найденные сейчас устройства целиком через VPN. Медленнее,'
                + ' а российские сайты могут не открываться.' },
        { id: 'none', title: 'Ничего, настрою сам',
          desc: 'Только запустить VPN. Правила потом — на странице «Маршрутизация».' },
    ];

    function renderRoute(body, state, w) {
        const r = state.route;
        body.innerHTML = `
            <p class="wizard-q">Что пускать через VPN?</p>
            <div class="choice-grid">
                ${MODES.map(m => `
                    <button class="choice-card ${r.mode === m.id ? 'active' : ''}" data-mode="${m.id}">
                        <div class="choice-title">${esc(m.title)}
                            ${m.badge ? `<span class="badge badge-accent">${esc(m.badge)}</span>` : ''}</div>
                        <div class="choice-desc">${esc(m.desc)}</div>
                    </button>`).join('')}
            </div>
            <div id="sw-route-detail" style="margin-top:14px;"></div>`;
        body.querySelectorAll('[data-mode]').forEach(b => b.onclick = () => {
            r.mode = b.dataset.mode;
            w.rerender();
        });
        const box = body.querySelector('#sw-route-detail');
        if (r.mode === 'sites') renderSites(box, state);
        else if (r.mode === 'devices' || r.mode === 'all') renderDevices(box, state, w);
    }

    function renderSites(box, state) {
        const r = state.route;
        box.innerHTML = `
            <label class="form-label">Сервисы</label>
            <div class="gen-actions">
                ${(opts.services || []).map(s => `
                    <button class="btn btn-sm ${r.services.includes(s.id) ? 'btn-primary' : 'btn-ghost'}"
                            data-svc="${esc(s.id)}">${r.services.includes(s.id) ? '✓ ' : ''}${esc(s.label)}</button>`).join('')}
            </div>
            <div class="form-group" style="margin-top:10px;">
                <label class="form-label">Другие сайты (необязательно)</label>
                <textarea class="form-input" id="sw-domains" rows="3"
                          placeholder="rutracker.org&#10;example.com">${esc((r.domains || []).join('\n'))}</textarea>
                <div class="form-hint">По одному в строке. Поддомены включаются сами.</div>
            </div>
            ${(opts.lists || []).length ? `
            <details><summary style="cursor:pointer;">Мои списки (${opts.lists.length})</summary>
                <div class="gen-actions" style="margin-top:8px;">
                    ${opts.lists.map(l => `
                        <label style="display:flex;gap:6px;align-items:center;">
                            <input type="checkbox" data-list="${esc(l.id)}" ${r.list_ids.includes(l.id) ? 'checked' : ''}>
                            ${esc(l.name)} <span class="text-muted">(${l.domains + l.cidrs})</span></label>`).join('')}
                </div>
            </details>` : ''}`;
        box.querySelectorAll('[data-svc]').forEach(b => b.onclick = () => {
            const id = b.dataset.svc;
            const i = r.services.indexOf(id);
            if (i >= 0) r.services.splice(i, 1); else r.services.push(id);
            renderSites(box, state);
        });
        box.querySelector('#sw-domains').oninput = (ev) => {
            r.domains = ev.target.value.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
        };
        box.querySelectorAll('[data-list]').forEach(cb => cb.onchange = () => {
            const id = cb.dataset.list;
            r.list_ids = r.list_ids.filter(x => x !== id);
            if (cb.checked) r.list_ids.push(id);
        });
    }

    async function renderDevices(box, state, w) {
        const r = state.route;
        if (!state.devices) {
            box.innerHTML = '<div class="text-muted">Ищу устройства в сети…</div>';
            if (state.devicesLoading) return;
            state.devicesLoading = true;
            try {
                const d = await API.get('/api/setup-wizard/devices');
                state.devices = d.devices || [];
            } catch (_) { state.devices = []; }
            state.devicesLoading = false;
            if (wizard && wizard.index === 3
                && ['devices', 'all'].includes(state.route.mode)) w.rerender();
            return;
        }
        if (r.mode === 'all') {
            box.innerHTML = state.devices.length
                ? `<div class="note-box warn">Через VPN пойдёт весь интернет
                       ${state.devices.length} найденных устройств. Новые устройства,
                       подключённые позже, добавьте на странице «Маршрутизация».</div>`
                : `<div class="note-box err">Устройства в сети не найдены — выберите
                       «Только нужные сайты» или «выбранные устройства».</div>`;
            return;
        }
        box.innerHTML = `
            <label class="form-label">Устройства</label>
            ${state.devices.length ? `
            <div style="display:grid;gap:6px;">
                ${state.devices.map(d => `
                    <label style="display:flex;gap:8px;align-items:center;">
                        <input type="checkbox" data-dev="${esc(d.ip)}"
                               ${r.devices.includes(d.ip) ? 'checked' : ''}>
                        <strong>${esc(d.hostname || 'без имени')}</strong>
                        <span class="text-muted">${esc(d.ip)}</span></label>`).join('')}
            </div>` : '<div class="text-muted">Устройства не найдены — впишите IP вручную.</div>'}
            <div class="form-group" style="margin-top:10px;">
                <label class="form-label">Или IP-адреса вручную</label>
                <input class="form-input" id="sw-dev-manual" placeholder="192.168.1.50, 192.168.1.51"
                       value="${esc(r.manual || '')}">
            </div>`;
        box.querySelectorAll('[data-dev]').forEach(cb => cb.onchange = () => {
            const ip = cb.dataset.dev;
            r.devices = r.devices.filter(x => x !== ip);
            if (cb.checked) r.devices.push(ip);
        });
        box.querySelector('#sw-dev-manual').oninput = (ev) => { r.manual = ev.target.value; };
    }

    function routeDevices(r) {
        const manual = (r.manual || '').split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
        return Array.from(new Set(r.devices.concat(manual)));
    }

    function validateRoute(state) {
        const r = state.route;
        if (r.mode === 'sites' && !r.services.length && !(r.domains || []).length && !r.list_ids.length)
            return 'Отметьте хотя бы один сервис или впишите сайт';
        if (r.mode === 'devices' && !routeDevices(r).length) return 'Выберите хотя бы одно устройство';
        if (r.mode === 'all' && !(state.devices || []).length) return 'Устройства в сети не найдены';
        return '';
    }

    // ─────────── шаг 5: запуск ───────────

    function plan(state) {
        const src = { kind: 'generate' };
        if (['warp', 'warp-masque', 'proton'].includes(state.source)) {
            const gen = { provider: state.source === 'proton' ? 'proton' : 'warp',
                          protocol: state.source === 'warp-masque' ? 'masque' : 'wireguard',
                          options: {} };
            if (state.source === 'proton') gen.country = state.country || '';
            if (state.source === 'warp') gen.options = { mask: 'quic', junk: 'light' };
            src.generate = gen;
        } else if (state.source === 'link') {
            src.kind = 'link'; src.link = state.link;
        } else if (state.source === 'paste') {
            src.kind = 'paste'; src.text = state.paste;
        } else {
            src.kind = 'existing'; src.name = state.existing;
        }
        const r = state.route;
        return {
            engine: state.engine, source: src, transport: state.transport,
            autostart: state.autostart,
            route: { mode: r.mode, services: r.services, domains: r.domains,
                     list_ids: r.list_ids, devices: routeDevices(r) },
        };
    }

    function renderLaunch(body, state) {
        if (state.launching) {
            body.innerHTML = `<div class="note-box">⏳ Сохраняю конфиг, запускаю
                программу и настраиваю маршрутизацию… Обычно до минуты.</div>`;
            return;
        }
        if (state.done) return renderDone(body, state);
        const e = engine(state);
        const r = state.route;
        const what = {
            sites: 'сайты: ' + ((opts.services || []).filter(s => r.services.includes(s.id))
                        .map(s => s.label).concat(r.domains || []).join(', ') || 'мои списки'),
            devices: 'устройства: ' + routeDevices(r).join(', '),
            all: 'все устройства (' + (state.devices || []).length + ')',
            none: 'ничего (настрою сам)',
        }[r.mode];
        body.innerHTML = `
            <p class="wizard-q">Всё готово к запуску</p>
            <div class="note-box">
                <div><b>Программа:</b> ${esc((ENGINE_INFO[e.id] || {}).title || e.label)}</div>
                <div><b>Сервер:</b> ${esc(SOURCES[state.source].title)}${state.source === 'proton' && state.country ? ' — ' + esc(state.country) : ''}</div>
                <div><b>Через VPN:</b> ${esc(what)}</div>
            </div>
            <label style="display:flex;gap:8px;align-items:center;margin:10px 0;">
                <input type="checkbox" id="sw-autostart" ${state.autostart ? 'checked' : ''}>
                Запускать автоматически после перезагрузки роутера</label>
            <details><summary style="cursor:pointer;">Дополнительно</summary>
                <div class="form-group" style="max-width:420px;margin-top:8px;">
                    <label class="form-label">Как дойти до VPN-сервиса при регистрации</label>
                    <select class="form-input" id="sw-transport">${transportOptions(state.transport, true)}</select>
                    <div class="form-hint">«Авто»: напрямую, а если не пускают — через
                        уже работающий обход.</div>
                </div>
            </details>`;
        body.querySelector('#sw-autostart').onchange = (ev) => { state.autostart = ev.target.checked; };
        body.querySelector('#sw-transport').onchange = (ev) => { state.transport = ev.target.value; };
    }

    async function launch(state) {
        try {
            state.done = await API.post('/api/setup-wizard/apply', plan(state),
                                        { timeout: 300000 });
        } catch (e) {
            state.done = { ok: false, error: String(e.message || e), steps: [] };
        }
    }

    const STEP_TITLES = { config: 'Конфиг', start: 'Запуск', autostart: 'Автозапуск',
                          route: 'Маршрутизация' };
    const ENGINE_PAGE = { awg: 'awg', usque: 'usque', singbox: 'singbox', mihomo: 'mihomo' };

    function renderDone(body, state) {
        const r = state.done;
        body.innerHTML = `
            ${r.ok
                ? `<div class="note-box ok"><b>Готово! VPN работает.</b>
                       ${r.method ? 'Интерфейс: ' + esc(r.iface) + '.' : ''}</div>`
                : `<div class="note-box err"><b>Не получилось:</b> ${esc(r.error || '')}</div>`}
            <ul style="list-style:none;padding:0;margin:10px 0;">
                ${(r.steps || []).map(s => `
                    <li style="margin:4px 0;">${s.ok ? '✅' : '❌'}
                        <b>${esc(STEP_TITLES[s.step] || s.step)}</b> — ${esc(s.detail)}</li>`).join('')}
            </ul>
            ${(r.warnings || []).map(x => `<div class="note-box warn">${esc(x)}</div>`).join('')}
            <div class="gen-actions">
                ${r.ok ? `
                    <a class="btn btn-primary" href="#routing">Маршрутизация →</a>
                    <a class="btn btn-ghost" href="#${ENGINE_PAGE[state.engine]}">Открыть программу</a>
                    <a class="btn btn-ghost" href="#tunnel-monitor">Мониторинг</a>`
                  : `<button class="btn btn-primary" id="sw-retry">Попробовать ещё раз</button>`}
                <button class="btn btn-ghost" id="sw-restart">Настроить ещё один</button>
            </div>`;
        const retry = body.querySelector('#sw-retry');
        if (retry) retry.onclick = () => wizard.next();
        body.querySelector('#sw-restart').onclick = () =>
            render(document.getElementById('sw-root').parentElement);
    }

    // ─────────── страница ───────────

    async function render(container) {
        clearTimeout(pollTimer);
        pollTimer = null;
        pollGen++;
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">Мастер настройки</h1>
                <p class="text-muted" style="margin:4px 0 0 0;">Настроим VPN для нужных
                    сайтов или устройств за пять шагов. Ничего не нужно знать заранее.</p>
            </div>
            <div class="card" id="sw-root"><div class="text-muted">Загрузка…</div></div>`;
        const root = container.querySelector('#sw-root');
        try {
            opts = await API.get('/api/setup-wizard/options');
        } catch (e) {
            root.innerHTML = `<div class="note-box err">Не удалось загрузить: ${esc(e.message || e)}</div>`;
            return;
        }
        const params = new URLSearchParams((location.hash.split('?')[1]) || '');
        const state = {
            engine: 'awg', source: '', transport: 'auto', autostart: true,
            route: { mode: 'sites', services: ['youtube'], domains: [],
                     list_ids: [], devices: [], manual: '' },
        };
        const pe = params.get('engine');
        if (pe && (opts.engines || []).some(e => e.id === pe)) {
            state.engine = pe;
            const cfg = params.get('config');
            if (cfg && engine(state).configs.includes(cfg)) {
                state.source = 'existing';
                state.existing = cfg;
            }
        }
        const steps = [
            { id: 'engine', title: 'Программа', render: renderEngine },
            { id: 'install', title: 'Установка', render: renderInstall,
              validate: s => engine(s).installed ? '' : 'Сначала установите программу' },
            { id: 'source', title: 'Сервер', render: renderSource, validate: validateSource },
            { id: 'route', title: 'Что пускать', render: renderRoute, validate: validateRoute },
            { id: 'launch', title: 'Запуск', render: renderLaunch },
        ];
        wizard = Wizard.create(root, {
            state, steps, finishLabel: 'Запустить',
            async onFinish(s, w) {
                if (s.done && s.done.ok) return;
                s.done = null;
                s.launching = true;
                w.rerender();
                await launch(s, w);
                s.launching = false;
                steps[4].hideNext = steps[4].hideBack = !!(s.done && s.done.ok);
                w.rerender();
            },
        });
        wizard.go(0);
    }

    function destroy() {
        clearTimeout(pollTimer);
        pollTimer = null;
        pollGen++;
        wizard = null;
    }

    return { render, destroy };
})();
