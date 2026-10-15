/**
 * config_check.js — кнопка «Проверить» для конфигов любого движка.
 *
 * Один бэкенд (POST /api/vpngen/check) для AmneziaWG, WARP/MASQUE (usque),
 * sing-box и mihomo: встроенный разбор, затем — если программа
 * установлена — она сама (`sing-box check`, `mihomo -t`). Ничего не
 * сохраняет. Проверить можно сохранённый конфиг (по имени) или текст из
 * редактора.
 *
 * Результат — в окне поверх страницы: так его видно на любой вкладке
 * (раньше «Проверить» в списке sing-box писал итог во вкладку редактора,
 * и в списке не появлялось ничего).
 *
 * Использование:
 *   ConfigCheck.show('awg', {name: 'warp'});
 *   ConfigCheck.show('singbox', {text: editorText, label: 'черновик'});
 */
const ConfigCheck = (() => {

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    async function run(target, src) {
        const body = { target };
        if (src && src.text != null) body.text = src.text;
        else body.name = (src && src.name) || '';
        return API.post('/api/vpngen/check', body, { timeout: 30000 });
    }

    function resultHtml(r) {
        const by = (r.checked_by || []).join(' + ');
        const head = r.ok
            ? `✅ Синтаксис в порядке${r.summary ? ': ' + esc(r.summary) : ''}`
            : '❌ Ошибки в конфиге:';
        return `<div class="note-box ${r.ok ? 'ok' : 'err'}" style="margin:0;">${head}
            ${r.ok ? '' : `<ul style="margin:4px 0 0 18px; padding:0;">${(r.errors || [])
                .map(x => `<li style="white-space:pre-wrap;">${esc(x)}</li>`).join('')}</ul>`}
            ${by ? `<div class="form-hint" style="margin-top:6px;">Проверено: ${esc(by)}</div>` : ''}
            ${(r.warnings || []).map(x => `<div class="form-hint">⚠ ${esc(x)}</div>`).join('')}
        </div>`;
    }

    async function show(target, src) {
        const label = (src && (src.label || src.name)) || '';
        let r;
        try {
            r = await run(target, src);
        } catch (e) {
            r = { ok: false, errors: ['проверка не выполнена: ' + (e.message || e)] };
        }
        await Confirm.show(`Проверка${label ? ' «' + esc(label) + '»' : ''}`,
                           resultHtml(r),
                           { confirmLabel: 'Закрыть', hideCancel: true, maxWidth: '560px' });
        return r;
    }

    return { run, show, resultHtml };
})();
