/* ═══════════════════════════════════════════════════════════
   BlueHound — Natural-Language Hunt Panel (FR-1)
   NL question → server translates to a Hunt Query IR → deterministic
   executor runs it against the cached session. Conversational follow-ups.
   All rendering is XSS-safe: text via esc()/textContent, never raw HTML
   interpolation of server values into attributes.
   ═══════════════════════════════════════════════════════════ */

const NLHuntPanel = {
    sessionId: null,
    conversationId: null,
    busy: false,

    init(sessionId) {
        this.sessionId = sessionId || null;
        this.conversationId = 'c_' + Math.random().toString(36).slice(2, 12);
        if (!this._bound) this.bindEvents();
        const thread = document.getElementById('nlhunt-thread');
        if (thread) thread.innerHTML = '';
        this._placeholder();
    },

    bindEvents() {
        this._bound = true;
        const ask = document.getElementById('nlhunt-ask-btn');
        const input = document.getElementById('nlhunt-input');
        const reset = document.getElementById('nlhunt-reset-btn');
        if (ask) ask.addEventListener('click', () => this.ask());
        if (input) input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.ask(); }
        });
        if (reset) reset.addEventListener('click', () => {
            this.conversationId = 'c_' + Math.random().toString(36).slice(2, 12);
            const t = document.getElementById('nlhunt-thread');
            if (t) t.innerHTML = '';
            this._placeholder();
        });
    },

    _placeholder() {
        const thread = document.getElementById('nlhunt-thread');
        if (!thread) return;
        const p = document.createElement('p');
        p.className = 'fr-placeholder';
        p.textContent = this.sessionId
            ? 'Ask a question to start hunting. Examples: “encoded powershell”, “DCSync replication”, “after lsass access what did the same account do”.'
            : 'Load a dataset first, then ask a hunting question.';
        thread.appendChild(p);
    },

    async ask() {
        if (this.busy) return;
        const input = document.getElementById('nlhunt-input');
        const question = (input?.value || '').trim();
        if (!question) return;
        if (!this.sessionId) {
            if (window.BlueHound) BlueHound._showToast('Load a dataset first.', 'error');
            return;
        }
        const thread = document.getElementById('nlhunt-thread');
        // Remove placeholder on first ask.
        if (thread && thread.querySelector('p') && thread.children.length === 1) thread.innerHTML = '';

        this._appendQuestion(question);
        input.value = '';
        const pending = this._appendPending();
        this.busy = true;
        try {
            const resp = await fetch('/api/hunt/nl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    question,
                    session_id: this.sessionId,
                    conversation_id: this.conversationId,
                }),
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || `Server error (${resp.status})`);
            pending.replaceWith(this._renderAnswer(data));
        } catch (err) {
            const e = document.createElement('div');
            e.className = 'nlhunt-card nlhunt-card-err';
            e.textContent = 'Error: ' + err.message;
            pending.replaceWith(e);
        } finally {
            this.busy = false;
        }
    },

    _appendQuestion(q) {
        const thread = document.getElementById('nlhunt-thread');
        const el = document.createElement('div');
        el.className = 'nlhunt-q';
        el.textContent = q;
        thread.appendChild(el);
        thread.scrollTop = thread.scrollHeight;
    },

    _appendPending() {
        const thread = document.getElementById('nlhunt-thread');
        const el = document.createElement('div');
        el.className = 'nlhunt-card fr-muted';
        el.textContent = '⏳ Translating to a hunt query and executing…';
        thread.appendChild(el);
        thread.scrollTop = thread.scrollHeight;
        return el;
    },

    _sourceBadge(source) {
        const map = { llm: '🤖 model', heuristic: '📋 heuristic', 'llm-skipped': '🛡 skipped (injection)' };
        return map[source] || this.esc(source || 'unknown');
    },

    _renderAnswer(data) {
        const card = document.createElement('div');
        card.className = 'nlhunt-card';

        // Header: explanation + provenance.
        const head = document.createElement('div');
        head.className = 'nlhunt-head';
        const expl = document.createElement('div');
        expl.className = 'fr-title';
        expl.textContent = data.explanation || `Matched ${Number(data.result_count) || 0} event(s).`;
        const prov = document.createElement('span');
        prov.className = 'fr-prov';
        prov.textContent = `${this._sourceBadge(data.source)} · ${data.model_id || ''}`;
        head.appendChild(expl); head.appendChild(prov);
        card.appendChild(head);

        if (data.llm_skipped_reason) {
            const warn = document.createElement('div');
            warn.className = 'fr-prov'; warn.style.color = 'var(--warning, #eab308)';
            warn.textContent = 'Model skipped: ' + data.llm_skipped_reason + ' — used deterministic fallback.';
            card.appendChild(warn);
        }

        // IR summary (steps + relations) — read-only, escaped JSON.
        card.appendChild(this._collapsible('Hunt Query IR', this._irSummary(data.ir)));

        // SIEM exports.
        const siem = (data.kql || data.spl || data.sigma);
        if (siem) {
            card.appendChild(this._siemTabs(data));
        }

        // Results table (bounded).
        card.appendChild(this._resultsTable(data.results || [], data.result_count, data.returned_result_count));

        const thread = document.getElementById('nlhunt-thread');
        if (thread) setTimeout(() => { thread.scrollTop = thread.scrollHeight; }, 0);
        return card;
    },

    _irSummary(ir) {
        const wrap = document.createElement('div');
        if (!ir) { wrap.textContent = '(none)'; return wrap; }
        (ir.steps || []).forEach(s => {
            const line = document.createElement('div');
            line.className = 'fr-ir-line';
            const preds = (s.predicates || []).map(p =>
                `${p.field} ${p.op} ${typeof p.value === 'object' ? JSON.stringify(p.value) : p.value}`
            ).join(s.match === 'all' ? ' AND ' : ' OR ');
            line.textContent = `step ${s.id}: ${preds}`;
            wrap.appendChild(line);
        });
        (ir.relations || []).forEach(r => {
            const line = document.createElement('div');
            line.className = 'fr-ir-rel';
            if (r.type === 'after') line.textContent = `relation: ${r.right} after ${r.left}`;
            else if (r.type === 'same') line.textContent = `relation: same ${r.field} (${(r.steps || []).join(', ')})`;
            else if (r.type === 'within') line.textContent = `relation: within ${r.seconds}s (${(r.steps || []).join(', ')})`;
            wrap.appendChild(line);
        });
        if (ir.use_previous) {
            const u = document.createElement('div');
            u.className = 'fr-prov';
            u.textContent = '(scoped to previous result)';
            wrap.appendChild(u);
        }
        return wrap;
    },

    _siemTabs(data) {
        const wrap = document.createElement('div');
        wrap.className = 'fr-collapse';
        const formats = [['kql', 'KQL'], ['spl', 'SPL'], ['sigma', 'Sigma']];
        const bar = document.createElement('div');
        bar.className = 'nlhunt-siem-bar';
        const pre = document.createElement('pre');
        pre.className = 'fr-code';
        const show = (fmt) => { pre.textContent = data[fmt] || '(empty)'; };
        formats.forEach(([fmt, label], i) => {
            const b = document.createElement('button');
            b.className = 'btn-ghost';
            b.className = 'btn-ghost';
            b.textContent = label;
            b.addEventListener('click', () => show(fmt));
            bar.appendChild(b);
            if (i === 0) show(fmt);
        });
        wrap.appendChild(bar);
        wrap.appendChild(pre);
        return wrap;
    },

    _resultsTable(results, total, returned) {
        const wrap = document.createElement('div');
        wrap.className = 'fr-collapse';
        const label = document.createElement('div');
        label.className = 'fr-prov';
        label.textContent = `Results: showing ${Number(returned) || results.length} of ${Number(total) || results.length}`;
        wrap.appendChild(label);
        if (!results.length) {
            const none = document.createElement('div');
            none.className = 'fr-muted';
            none.textContent = 'No matching events.';
            wrap.appendChild(none);
            return wrap;
        }
        const table = document.createElement('table');
        table.className = 'nlhunt-table';
        const cols = ['timestamp', 'hostname', 'user_name', 'process_name', 'commandline'];
        const thead = document.createElement('tr');
        cols.forEach(c => {
            const th = document.createElement('th');
            
            th.textContent = c;
            thead.appendChild(th);
        });
        table.appendChild(thead);
        results.slice(0, 50).forEach(ev => {
            const tr = document.createElement('tr');
            cols.forEach(c => {
                const td = document.createElement('td');
                
                let v = ev[c];
                if (c === 'commandline') td.title = String(v || '');
                td.textContent = v == null ? '' : String(v);
                tr.appendChild(td);
            });
            table.appendChild(tr);
        });
        wrap.appendChild(table);
        return wrap;
    },

    _collapsible(title, contentEl) {
        const det = document.createElement('details');
        det.className = 'fr-collapse';
        const sum = document.createElement('summary');
        sum.className = 'fr-summary';
        sum.textContent = title;
        det.appendChild(sum);
        det.appendChild(contentEl);
        return det;
    },

    esc(s) {
        if (s === 0) return '0';
        if (!s) return '';
        const d = document.createElement('div');
        d.textContent = String(s);
        return d.innerHTML;
    },
};
