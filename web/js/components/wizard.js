/**
 * wizard.js — пошаговый мастер: заголовок шагов, тело, «Назад/Далее».
 *
 * Использование:
 *   const w = Wizard.create(container, {
 *       steps: [
 *           { id: 'what', title: 'Что',
 *             render(body, state, w) { body.innerHTML = '…'; },
 *             validate(state) { return state.x ? '' : 'Выберите …'; },
 *             skip(state) { return false; },
 *             nextLabel: 'Сгенерировать',   // подпись «Далее» на этом шаге
 *             hideNext: true },             // шаг без кнопки «Далее»
 *           …
 *       ],
 *       state: {},                 // общий объект, шаги пишут в него
 *       finishLabel: 'Готово',
 *       onFinish(state, w) { … },  // может вернуть Promise
 *   });
 *   w.go(0); w.next(); w.back(); w.refresh(); w.setBusy(true)
 *
 * Шаг сам отвечает за свою разметку и пишет выбор в `state`; мастер —
 * только за навигацию: не пускает дальше, пока validate() возвращает
 * текст ошибки, и пропускает шаги, у которых skip(state) истинно.
 * Разметка держится на общих классах .wizard-* (style.css), поэтому и
 * генератор конфигов, и мастер sing-box/mihomo выглядят одинаково.
 */
const Wizard = (() => {
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function create(container, opts) {
        const steps = opts.steps || [];
        const state = opts.state || {};
        let index = 0;
        let busy = false;

        container.innerHTML = `
            <div class="wizard">
                <ol class="wizard-steps"></ol>
                <div class="wizard-error" style="display:none;"></div>
                <div class="wizard-body"></div>
                <div class="wizard-nav">
                    <button class="btn btn-ghost" data-wz="back">← Назад</button>
                    <button class="btn btn-primary" data-wz="next">Далее →</button>
                </div>
            </div>`;
        const head = container.querySelector('.wizard-steps');
        const body = container.querySelector('.wizard-body');
        const errBox = container.querySelector('.wizard-error');
        const btnBack = container.querySelector('[data-wz="back"]');
        const btnNext = container.querySelector('[data-wz="next"]');

        function visible() {
            return steps.map((s, i) => i)
                .filter(i => !(steps[i].skip && steps[i].skip(state)));
        }

        function showError(msg) {
            errBox.textContent = msg || '';
            errBox.style.display = msg ? '' : 'none';
        }

        function paintHead() {
            const vis = visible();
            head.innerHTML = vis.map((i, n) => {
                const cls = i === index ? 'active' : (i < index ? 'done' : '');
                return `<li class="wizard-step ${cls}" data-wz-step="${i}">
                            <span class="wizard-num">${n + 1}</span>
                            <span>${esc(steps[i].title)}</span></li>`;
            }).join('');
        }

        function paintNav() {
            const vis = visible();
            const last = vis[vis.length - 1] === index;
            btnBack.style.visibility = vis[0] === index ? 'hidden' : '';
            const step = steps[index];
            btnNext.textContent = last ? (opts.finishLabel || 'Готово')
                                       : ((step && step.nextLabel) || 'Далее →');
            btnNext.style.display = step && step.hideNext ? 'none' : '';
            btnNext.disabled = busy;
            btnBack.disabled = busy;
        }

        function go(i) {
            index = Math.max(0, Math.min(i, steps.length - 1));
            if (steps[index].skip && steps[index].skip(state)) {
                const vis = visible();
                index = vis.find(v => v >= index) ?? vis[vis.length - 1];
            }
            showError('');
            paintHead();
            body.innerHTML = '';
            steps[index].render(body, state, api);
            paintNav();
            if (container.scrollIntoView && opts.scroll !== false) {
                container.scrollIntoView({ block: 'start', behavior: 'smooth' });
            }
        }

        async function next() {
            if (busy) return;
            const step = steps[index];
            const err = step.validate ? step.validate(state) : '';
            if (err) { showError(err); return; }
            const vis = visible();
            const pos = vis.indexOf(index);
            if (pos === vis.length - 1) {
                if (opts.onFinish) {
                    setBusy(true);
                    try { await opts.onFinish(state, api); }
                    finally { setBusy(false); }
                }
                return;
            }
            go(vis[pos + 1]);
        }

        function back() {
            if (busy) return;
            const vis = visible();
            const pos = vis.indexOf(index);
            if (pos > 0) go(vis[pos - 1]);
        }

        function setBusy(on) {
            busy = !!on;
            paintNav();
            btnNext.classList.toggle('loading', busy);
        }

        btnNext.addEventListener('click', next);
        btnBack.addEventListener('click', back);
        head.addEventListener('click', (e) => {
            const li = e.target.closest('[data-wz-step]');
            if (!li || busy) return;
            const i = Number(li.dataset.wzStep);
            // Назад — всегда можно, вперёд — только по «Далее» (с проверкой).
            if (i < index) go(i);
        });

        const api = {
            state, go, next, back, setBusy,
            refresh() { paintHead(); paintNav(); },
            rerender() { go(index); },
            error: showError,
            get index() { return index; },
        };
        return api;
    }

    return { create, esc };
})();
