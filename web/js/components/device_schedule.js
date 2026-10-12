/**
 * device_schedule.js — карточка «Расписание по устройствам» (issue #381).
 *
 * В окна правил выбранные устройства идут мимо nfqws2 (обход для них
 * выключен), остальные — с обходом всегда. Сервер: GET/POST
 * /api/device-schedule (core/device_schedule.py), список устройств —
 * /api/devices. Монтируется в страницу «Управление».
 */

const DeviceSchedule = (() => {
    const DAYS = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'];

    let host = null;
    let st = { enabled: false, tz_offset: '', rules: [] };
    let status = {};
    let devices = [];
    let dirty = false;

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    async function mount(el) {
        host = el;
        dirty = false;
        host.innerHTML = '<div class="text-muted" style="font-size:12px;">Загрузка…</div>';
        try {
            const r = await API.get('/api/device-schedule');
            st = fromServer(r.settings);
            status = r.status || {};
        } catch (e) {
            host.innerHTML = `<div class="text-muted">Ошибка: ${esc(e.message)}</div>`;
            return;
        }
        draw();
        try {
            const r = await API.get('/api/devices');
            devices = (r && r.devices) || [];
            if (!dirty) draw();
        } catch (_) { /* список устройств — только подсказка */ }
    }

    // Сервер хранит «каждый день» пустым списком; в форме — все семь
    // галок, чтобы снятая последняя галка не превращалась в «каждый день».
    function fromServer(settings) {
        const out = Object.assign({ enabled: false, tz_offset: '', rules: [] }, settings);
        // Битое правило из settings.json приходит как есть (с полем error):
        // приводим поля к форме, чтобы его можно было поправить.
        out.rules = (out.rules || []).map(r => Object.assign({}, r, {
            devices: Array.isArray(r.devices) ? r.devices
                : String(r.devices || '').split(/[\s,;]+/).filter(Boolean),
            days: (Array.isArray(r.days) && r.days.length)
                ? r.days.map(Number) : [1, 2, 3, 4, 5, 6, 7] }));
        return out;
    }

    // Имя устройства: запомненное в правиле при выборе из сети (оно есть,
    // даже когда устройство выключено), иначе — из текущего списка сети.
    function liveName(token) {
        const t = String(token || '').toLowerCase();
        const d = devices.find(x => (x.mac || '').toLowerCase() === t || x.ip === t);
        return d && d.hostname && d.hostname !== t ? d.hostname : '';
    }

    function allNames() {
        return Object.assign({}, ...(st.rules || []).map(r => r.names || {}));
    }

    // «Имя (MAC)» — по имени ориентироваться проще (issue #381).
    function deviceLabel(token, names) {
        const name = (names || {})[token] || liveName(token);
        return name ? `${name} (${token})` : token;
    }

    // Адрес из статуса («мимо обхода» — уже IP, в который превратился MAC):
    // ищем устройство с этим IP и подписываем его именем.
    function addrLabel(addr) {
        const names = allNames();
        const d = devices.find(x => x.ip === addr);
        const name = names[addr] || (d && (names[(d.mac || '').toLowerCase()]
                                           || (d.hostname !== addr && d.hostname)));
        return name ? `${name} (${addr})` : addr;
    }

    function normToken(v) {
        return String(v || '').trim().toLowerCase().replace(/-/g, ':');
    }

    function statusHtml() {
        if (!st.enabled) {
            return '<span class="text-muted">Выключено — обход для всех устройств.</span>';
        }
        const parts = [];
        parts.push(`Время роутера: <strong>${esc(status.router_time || '?')}</strong>`
            + (st.tz_offset ? ` (сдвиг ${esc(st.tz_offset)})` : ''));
        if ((status.active_rules || []).length) {
            parts.push(`Действует: <strong>${esc(status.active_rules.join(', '))}</strong>`);
            parts.push(`Мимо обхода: ${(status.excluded || []).length
                ? esc(status.excluded.map(addrLabel).join(', ')) : '—'}`);
        } else {
            parts.push('Сейчас ни одно правило не действует — обход для всех.');
        }
        if ((status.unresolved || []).length) {
            parts.push(`<span style="color:#e58;">Не найдены в сети (обход у них есть): `
                + `${esc(status.unresolved.map(m => deviceLabel(m, allNames())).join(', '))}</span>`);
        }
        (st.errors || []).filter(e => e.startsWith('tz_offset')).forEach(e => {
            parts.push(`<span style="color:#e58;">${esc(e)} — используется время системы</span>`);
        });
        if (status.error) {
            parts.push(`<span style="color:#e58;">Ошибка: ${esc(status.error)}</span>`);
        }
        return parts.join('<br>');
    }

    function ruleHtml(r, i) {
        const days = r.days || [];
        return `
        <div class="card" style="margin:8px 0; padding:10px 12px;">
            ${r.error ? `<div style="color:#e58; font-size:12px; margin-bottom:6px;">
                Правило не действует: ${esc(r.error)}. Исправьте или удалите его.</div>` : ''}
            <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
                <label style="display:flex; align-items:center; gap:6px;">
                    <input type="checkbox" data-ds="enabled" data-i="${i}" ${r.enabled !== false ? 'checked' : ''}>
                </label>
                <input type="text" class="form-input" data-ds="name" data-i="${i}"
                       placeholder="Название (например, «Дети днём»)" value="${esc(r.name)}"
                       style="flex:1; min-width:160px;">
                <span class="text-muted" style="font-size:12px;">с</span>
                <input type="time" class="form-input" data-ds="from" data-i="${i}" value="${esc(r.from || '09:00')}" style="width:110px;">
                <span class="text-muted" style="font-size:12px;">до</span>
                <input type="time" class="form-input" data-ds="to" data-i="${i}" value="${esc(r.to || '19:00')}" style="width:110px;">
                <button class="btn btn-ghost btn-sm" data-ds-action="del" data-i="${i}" title="Удалить правило">✕</button>
            </div>
            <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:8px; font-size:12px;">
                ${DAYS.map((d, k) => `
                <label style="display:flex; align-items:center; gap:3px;">
                    <input type="checkbox" data-ds="day" data-i="${i}" data-day="${k + 1}"
                           ${days.includes(k + 1) ? 'checked' : ''}>${d}
                </label>`).join('')}
            </div>
            <div style="margin-top:8px;">
                <!-- По устройству на строку: так список читается легче (issue #381). -->
                <div style="display:flex; flex-direction:column; gap:4px; max-width:520px;">
                    ${(r.devices || []).map((d, k) => `
                    <div title="${esc(d)}" style="display:flex; align-items:center; gap:8px;
                                 padding:3px 4px 3px 10px; border-radius:8px; font-size:12px;
                                 background:var(--bg-secondary); border:1px solid var(--border, transparent);">
                        <span style="flex:1; min-width:0; overflow-wrap:anywhere;">${esc(deviceLabel(d, r.names))}</span>
                        <button class="btn btn-ghost btn-sm" data-ds-action="rmdev" data-i="${i}" data-k="${k}"
                                title="Убрать устройство" style="padding:0 6px; line-height:1.4;">✕</button>
                    </div>`).join('')
                    || '<span class="text-muted" style="font-size:12px;">Устройства не выбраны.</span>'}
                </div>
                <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center; margin-top:6px;">
                    ${devices.length ? `
                    <select class="form-select" data-ds-action="pick" data-i="${i}" style="font-size:12px; max-width:100%;">
                        <option value="">+ добавить устройство из сети…</option>
                        ${devices.map(d => `<option value="${esc(d.mac || d.ip)}">
                            ${esc(d.hostname && d.hostname !== d.ip ? d.hostname : d.ip)}
                            (${esc(d.mac || d.ip)})${d.mac ? ' — ' + esc(d.ip) : ''}</option>`).join('')}
                    </select>` : ''}
                    <input type="text" class="form-input" data-ds-manual="${i}"
                           placeholder="вручную: IP или MAC"
                           style="width:210px; font-size:12px; font-family:monospace;">
                    <button class="btn btn-ghost btn-sm" data-ds-action="adddev" data-i="${i}">Добавить</button>
                </div>
            </div>
        </div>`;
    }

    function draw() {
        if (!host) return;
        host.innerHTML = `
            <div class="form-hint" style="margin-bottom:8px;">
                В окна правил выбранные устройства идут <strong>мимо nfqws2</strong>:
                обход для них выключен (например, YouTube на детских устройствах днём),
                остальные устройства — с обходом всегда. Окно вида 22:00–07:00 идёт
                через полночь. Устройство лучше указывать по MAC — так учитываются
                его IPv6 и смена адреса. Уже открытое соединение исключение не
                обрывает: правило действует на новые соединения.
            </div>
            <label style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                <input type="checkbox" data-ds="on" ${st.enabled ? 'checked' : ''}>
                <strong>Включить расписание</strong>
            </label>
            <div style="font-size:12px; margin-bottom:8px;" id="ds-status">${statusHtml()}</div>
            <div id="ds-rules">${(st.rules || []).map(ruleHtml).join('')
                || '<div class="text-muted" style="font-size:12px;">Правил нет.</div>'}</div>
            <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-top:8px;">
                <button class="btn btn-ghost btn-sm" data-ds-action="add">+ Правило</button>
                <span class="expert-only" style="font-size:12px;">
                    Сдвиг часового пояса:
                    <input type="text" class="form-input" data-ds="tz" value="${esc(st.tz_offset)}"
                           placeholder="время системы" style="width:110px;"
                           title="Если время роутера выше не совпадает с местным (на Entware часто UTC) — укажите, например, +03:00">
                </span>
                <button class="btn btn-primary btn-sm" data-ds-action="save" style="margin-left:auto;">
                    Сохранить и применить
                </button>
            </div>`;
        host.oninput = onInput;
        host.onchange = onInput;
        host.onclick = onClick;
        host.onkeydown = e => {
            if (e.key === 'Enter' && e.target.dataset && e.target.dataset.dsManual != null) {
                e.preventDefault();
                addManual(+e.target.dataset.dsManual);
            }
        };
    }

    function onInput(e) {
        const t = e.target;
        const f = t.dataset && t.dataset.ds;
        if (t.dataset && t.dataset.dsAction === 'pick' && e.type === 'change') {
            const v = normToken(t.value);
            const d = devices.find(x => normToken(x.mac || x.ip) === v);
            addDevice(+t.dataset.i, v, d && d.hostname !== d.ip ? d.hostname : '');
            return;
        }
        if (!f) return;
        dirty = true;
        if (f === 'on') { st.enabled = t.checked; return; }
        if (f === 'tz') { st.tz_offset = t.value.trim(); return; }
        const r = st.rules[+t.dataset.i];
        if (!r) return;
        delete r.error;
        if (f === 'enabled') r.enabled = t.checked;
        else if (f === 'name') r.name = t.value;
        else if (f === 'from' || f === 'to') r[f] = t.value;
        else if (f === 'day') {
            const d = +t.dataset.day;
            const cur = r.days || [];
            r.days = t.checked ? Array.from(new Set(cur.concat([d]))).sort()
                               : cur.filter(x => x !== d);
        }
    }

    function addDevice(i, token, name) {
        const r = st.rules[i];
        if (!r || !token) return;
        delete r.error;
        if (!(r.devices || []).includes(token)) {
            r.devices = (r.devices || []).concat([token]);
        }
        if (name) r.names = Object.assign({}, r.names || {}, { [token]: name });
        dirty = true;
        draw();
    }

    function addManual(i) {
        const el = host.querySelector(`[data-ds-manual="${i}"]`);
        const tokens = String(el && el.value || '').split(/[\s,;]+/).map(normToken).filter(Boolean);
        tokens.forEach(t => addDevice(i, t, ''));
    }

    async function onClick(e) {
        const b = e.target.closest('[data-ds-action]');
        if (!b || b.tagName === 'SELECT') return;
        const a = b.dataset.dsAction;
        if (a === 'add') {
            st.rules = (st.rules || []).concat([{
                name: '', enabled: true, devices: [], days: [1, 2, 3, 4, 5],
                from: '09:00', to: '19:00' }]);
            dirty = true;
            draw();
        } else if (a === 'adddev') {
            addManual(+b.dataset.i);
        } else if (a === 'rmdev') {
            const r = st.rules[+b.dataset.i];
            const token = r.devices[+b.dataset.k];
            r.devices.splice(+b.dataset.k, 1);
            if (r.names) delete r.names[token];
            delete r.error;
            dirty = true;
            draw();
        } else if (a === 'del') {
            st.rules.splice(+b.dataset.i, 1);
            dirty = true;
            draw();
        } else if (a === 'save') {
            const bad = st.rules.find(r => !(r.days || []).length);
            if (bad) { Toast.error('Отметьте хотя бы один день недели'); return; }
            if (st.rules.find(r => !(r.devices || []).length)) {
                Toast.error('В правиле не выбрано ни одного устройства'); return;
            }
            try {
                // Все дни отмечены — храним пустой список («каждый день»).
                const body = Object.assign({}, st, {
                    rules: st.rules.map(r => Object.assign({}, r, {
                        days: (r.days || []).length === 7 ? [] : r.days })) });
                const r = await API.post('/api/device-schedule', body);
                st = fromServer(r.settings);
                status = r.status || {};
                dirty = false;
                draw();
                Toast.success('Расписание сохранено');
            } catch (err) {
                Toast.error(err.message);
            }
        }
    }

    return { mount };
})();
