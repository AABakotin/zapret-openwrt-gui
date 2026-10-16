/**
 * safe_apply.js — баннер «Применение с проверкой» поверх любой страницы.
 *
 * Бэкенд — core/safe_apply.py (/api/safe-apply*): замер сайтов до,
 * применение, замер после, ожидание подтверждения со сроком, откат.
 * Баннер виден на всех страницах: подтверждать или откатывать удобно
 * оттуда, где человек проверял, а не возвращаясь на «Стратегии».
 *
 * Опрос — только пока проверка идёт; в покое запросов нет.
 */

const SafeApply = (() => {
    let timer = null;
    let session = null;
    // started сессии, чей итог уже закрыли крестиком.
    let dismissed = null;

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function el() {
        let box = document.getElementById('safe-apply-banner');
        if (!box) {
            const content = document.getElementById('content');
            if (!content) return null;
            box = document.createElement('div');
            box.id = 'safe-apply-banner';
            box.style.cssText = 'display:none; margin:12px 16px 0;';
            content.insertBefore(box, content.firstChild);
        }
        return box;
    }

    function isActive(s) {
        return !!s && ['probing', 'applying', 'waiting', 'rolling_back']
            .includes(s.phase);
    }

    function mmss(sec) {
        sec = Math.max(0, sec | 0);
        return Math.floor(sec / 60) + ':' + String(sec % 60).padStart(2, '0');
    }

    function probeLine(s) {
        const a = s.after, b = s.before;
        if (!a || !b || !a.total) return '';
        let line = 'Сайты мониторинга: открывается ' + a.ok + ' из ' + a.total
            + ' (до смены — ' + b.ok + ').';
        const v = s.verdict || {};
        if ((v.lost || []).length) line += ' Перестали: ' + v.lost.join(', ') + '.';
        if ((v.gained || []).length) line += ' Заработали: ' + v.gained.join(', ') + '.';
        return line;
    }

    function render() {
        const box = el();
        if (!box) return;
        const s = session;
        if (!s || (!isActive(s) && (s.started === dismissed
                || Date.now() / 1000 - (s.finished || 0) > 600
                || s.phase === 'confirmed' || s.phase === 'superseded'))) {
            box.style.display = 'none';
            box.innerHTML = '';
            return;
        }
        const name = esc(s.strategy_name || s.strategy_id);
        let cls = 'alert-info', title = '', body = '', buttons = '';
        if (s.phase === 'probing') {
            title = 'Проверяю, что открывается сейчас…';
            body = 'Потом применю «' + name + '» и проверю ещё раз.';
        } else if (s.phase === 'applying') {
            title = 'Применяю «' + name + '»…';
            body = 'Через несколько секунд проверю сайты мониторинга.';
        } else if (s.phase === 'rolling_back') {
            cls = 'alert-warning';
            title = 'Возвращаю прежнее состояние…';
            body = esc(s.reason || '');
        } else if (s.phase === 'waiting') {
            cls = 'alert-warning';
            title = 'Стратегия «' + name + '» применена — всё работает?';
            body = esc(probeLine(s)) + ' Если не подтвердить, через <b>'
                + mmss(s.left) + '</b> вернётся прежнее.';
            buttons = '<button class="btn btn-primary btn-sm" onclick="SafeApply.confirm()">Всё работает</button>'
                + '<button class="btn btn-ghost btn-sm" onclick="SafeApply.rollback()">Откатить</button>';
        } else if (s.phase === 'rolled_back') {
            cls = 'alert-danger';
            title = '«' + name + '» откачена';
            body = esc(s.reason || '') + (s.result ? ' — ' + esc(s.result) : '')
                + (probeLine(s) ? '<br>' + esc(probeLine(s)) : '');
            buttons = '<button class="btn btn-ghost btn-sm" onclick="SafeApply.dismiss()">Закрыть</button>';
        } else if (s.phase === 'failed') {
            cls = 'alert-danger';
            title = 'Проверка не началась';
            body = esc(s.reason || '');
            buttons = '<button class="btn btn-ghost btn-sm" onclick="SafeApply.dismiss()">Закрыть</button>';
        }
        box.innerHTML = '<div class="alert ' + cls + '" style="display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin:0;">'
            + '<div style="flex:1; min-width:220px;"><div class="alert-title">' + title + '</div>'
            + '<p>' + body + '</p></div>'
            + '<div style="display:flex; gap:8px;">' + buttons + '</div></div>';
        box.style.display = '';
    }

    async function poll() {
        try {
            const r = await API.get('/api/safe-apply');
            const prev = session;
            session = r.session || null;
            if (prev && isActive(prev) && session && !isActive(session)) {
                if (session.phase === 'confirmed') Toast.success('Стратегия оставлена и отмечена рабочей');
                // Страница могла показывать старую активную стратегию.
                window.dispatchEvent(new CustomEvent('safeapply:done',
                    { detail: session }));
            }
        } catch (_) { /* сеть моргнула — попробуем на следующем тике */ }
        render();
        schedule();
    }

    function schedule() {
        if (timer) clearTimeout(timer);
        timer = null;
        if (isActive(session)) timer = setTimeout(poll, 2000);
    }

    async function start(strategyId, timeout) {
        try {
            const r = await API.post('/api/safe-apply/start',
                { strategy_id: strategyId, timeout: timeout || 180 });
            if (!r.ok) {
                Toast.error(r.error || 'Не удалось начать проверку');
                return false;
            }
            session = r.session;
            render();
            schedule();
            return true;
        } catch (e) {
            Toast.error(e.message);
            return false;
        }
    }

    async function confirm() {
        try {
            const r = await API.post('/api/safe-apply/confirm', {});
            if (!r.ok) Toast.error(r.error || 'Не удалось подтвердить');
        } catch (e) { Toast.error(e.message); }
        poll();
    }

    async function rollback() {
        try {
            const r = await API.post('/api/safe-apply/rollback', {});
            if (!r.ok) Toast.error(r.error || 'Откат не удался');
        } catch (e) { Toast.error(e.message); }
        poll();
    }

    function dismiss() {
        if (session) dismissed = session.started;
        render();
    }

    function init() { poll(); }

    return { init, start, confirm, rollback, dismiss, poll, _render: render };
})();
