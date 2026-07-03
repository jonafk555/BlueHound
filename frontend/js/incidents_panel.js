/* ═══════════════════════════════════════════════════════════
   BlueHound — Incidents Panel
   LLM/rules lead (severity + suggested priority); human-on-the-loop triage.
   ═══════════════════════════════════════════════════════════ */

const IncidentsPanel = {
    incidents: [],
    hideClosed: false,

    STATUS_LABELS: {
        new: 'New',
        pending_fix: 'Pending Fix',
        remediated: 'Remediated',
        excluded: 'Excluded',
        risk_accepted: 'Risk Accepted',
    },
    PRIORITY_LABELS: {
        P0: 'P0 · Critical',
        P1: 'P1 · High',
        P2: 'P2 · Medium',
        P3: 'P3 · Low',
    },
    CLOSED: new Set(['remediated', 'excluded', 'risk_accepted']),

    render(incidents) {
        this.incidents = Array.isArray(incidents) ? incidents : [];
        if (!this._bound) this.bindEvents();
        this.renderSummary();
        this.renderList();
    },

    bindEvents() {
        this._bound = true;
        const hc = document.getElementById('inc-hide-closed');
        if (hc) hc.addEventListener('change', () => {
            this.hideClosed = hc.checked;
            this.renderList();
        });
    },

    // Whitelist class tokens — never interpolate raw values into class="" (escapeHtml
    // doesn't escape quotes). Mirrors the graph.js _sevClassToken hardening.
    _sevToken(s) {
        const v = String(s || '').toLowerCase();
        return ['critical', 'high', 'medium', 'low', 'benign'].includes(v) ? v : 'unknown';
    },
    _prioToken(p) {
        const v = String(p || '').toUpperCase();
        return ['P0', 'P1', 'P2', 'P3'].includes(v) ? v : 'P3';
    },
    _statusToken(s) {
        const v = String(s || '').toLowerCase();
        return Object.prototype.hasOwnProperty.call(this.STATUS_LABELS, v) ? v : 'new';
    },

    renderSummary() {
        const el = document.getElementById('inc-summary');
        if (!el) return;
        const open = this.incidents.filter(i => !this.CLOSED.has(i.triage?.status));
        const byPrio = { P0: 0, P1: 0, P2: 0, P3: 0 };
        open.forEach(i => {
            const p = this._prioToken(i.triage?.priority || i.suggested_priority);
            byPrio[p]++;
        });
        const total = this.incidents.length;
        const closed = total - open.length;
        el.innerHTML = `
            <span class="inc-stat">Incidents <b>${total}</b></span>
            <span class="inc-stat inc-stat-open">Open <b>${open.length}</b></span>
            <span class="inc-stat">Resolved <b>${closed}</b></span>
            <span class="inc-chip prio-P0">P0 ${byPrio.P0}</span>
            <span class="inc-chip prio-P1">P1 ${byPrio.P1}</span>
            <span class="inc-chip prio-P2">P2 ${byPrio.P2}</span>
            <span class="inc-chip prio-P3">P3 ${byPrio.P3}</span>`;
    },

    renderList() {
        const list = document.getElementById('incidents-list');
        if (!list) return;
        list.innerHTML = '';

        let shown = this.incidents;
        if (this.hideClosed) shown = shown.filter(i => !this.CLOSED.has(i.triage?.status));

        if (shown.length === 0) {
            const p = document.createElement('p');
            p.style.cssText = 'color:var(--text-muted);padding:24px;text-align:center;';
            p.textContent = this.incidents.length === 0
                ? 'No correlated incidents — load a dataset with findings.'
                : 'No incidents match the current filter.';
            list.appendChild(p);
            return;
        }

        shown.forEach(inc => list.appendChild(this.renderCard(inc)));
    },

    renderCard(inc) {
        const sevTok = this._sevToken(inc.severity);
        const status = this._statusToken(inc.triage?.status);
        const prio = this._prioToken(inc.triage?.priority || inc.suggested_priority);
        const isClosed = this.CLOSED.has(status);

        const card = document.createElement('div');
        card.className = `incident-card sev-${sevTok}${isClosed ? ' incident-closed' : ''}`;
        card.dataset.incidentId = inc.id;

        const tactics = (inc.tactics || []).map(t => `<span class="inc-tag">${this.esc(t)}</span>`).join('');
        const hosts = (inc.hosts || []).map(h => `<span class="inc-tag host-tag">${this.esc(h)}</span>`).join('');
        const users = (inc.users || []).map(u => `<span class="inc-tag user-tag">${this.esc(u)}</span>`).join('');
        const active = Number(inc.active_finding_count != null ? inc.active_finding_count : (inc.findings || []).length);
        const total = (inc.findings || []).length;
        const chainLabel = active === total
            ? `${total} event(s) in chain`
            : `${active} of ${total} event(s) active (${total - active} excluded)`;

        const statusOpts = Object.entries(this.STATUS_LABELS).map(([v, label]) =>
            `<option value="${v}"${v === status ? ' selected' : ''}>${this.esc(label)}</option>`).join('');
        const prioOpts = Object.entries(this.PRIORITY_LABELS).map(([v, label]) =>
            `<option value="${v}"${v === prio ? ' selected' : ''}>${this.esc(label)}</option>`).join('');

        card.innerHTML = `
            <div class="incident-head">
                <span class="detail-sev-badge badge-${sevTok}">${this.esc(inc.severity)}</span>
                <span class="inc-prio-badge prio-${prio}" title="Suggested priority (LLM/rules)">Suggested ${this.esc(inc.suggested_priority)}</span>
                <span class="incident-title">${this.esc(inc.title)}</span>
                <span class="inc-status-pill status-${status}">${this.esc(this.STATUS_LABELS[status])}</span>
            </div>
            <div class="incident-narrative">${this.esc(inc.narrative || '')}</div>
            <div class="incident-tags">
                ${inc.tactic_ids && inc.tactic_ids.length ? `<span class="inc-tag-label">ATT&CK</span>${(inc.tactic_ids).map(t => `<span class="inc-tag mitre">${this.esc(t)}</span>`).join('')}` : ''}
            </div>
            <div class="incident-tags">${hosts}${users}${tactics}</div>
            <details class="incident-findings" open>
                <summary>Attack chain — ${this.esc(chainLabel)} · exclude false positives</summary>
                <div class="inc-chain"></div>
            </details>
            <div class="incident-triage">
                <div class="triage-field">
                    <label>Status</label>
                    <select class="triage-status">${statusOpts}</select>
                </div>
                <div class="triage-field">
                    <label>Priority</label>
                    <select class="triage-priority">${prioOpts}</select>
                </div>
                <div class="triage-field triage-note-field">
                    <label>Note</label>
                    <input class="triage-note" type="text" maxlength="2000" placeholder="Analyst note…">
                </div>
                <button class="btn-primary triage-save">Save</button>
                <span class="triage-saved" style="display:none;">✓ saved</span>
            </div>`;

        // Set the note via DOM property (NOT an HTML attribute) — esc() does not
        // escape quotes, so interpolating into value="" would allow attribute
        // injection (caught by S-XSS-04). .value assignment is parser-safe.
        card.querySelector('.triage-note').value = inc.triage?.note || '';

        // Attack chain rows with per-event exclude toggles (DOM-built, XSS-safe).
        const chain = card.querySelector('.inc-chain');
        (inc.findings || []).forEach(f => chain.appendChild(this._renderChainRow(inc, f, card)));

        const saveBtn = card.querySelector('.triage-save');
        saveBtn.addEventListener('click', () => this.saveTriage(inc, card));
        return card;
    },

    // One event in the attack chain + an exclude/restore toggle (per-event triage).
    _renderChainRow(inc, f, card) {
        const row = document.createElement('div');
        row.className = 'inc-finding' + (f.excluded ? ' inc-finding-excluded' : '');

        const sev = document.createElement('span');
        sev.className = 'finding-sev ' + this._sevToken(f.severity);
        sev.textContent = (f.severity || '').toUpperCase();

        const name = document.createElement('span');
        name.className = 'inc-finding-name';
        name.textContent = f.rule_name || '';

        const meta = document.createElement('span');
        meta.className = 'inc-finding-meta';
        meta.textContent = `${f.process_name || ''} · ${(f.timestamp || '').replace('T', ' ').replace('Z', '')}`;

        const btn = document.createElement('button');
        btn.className = 'inc-exclude-btn';
        btn.textContent = f.excluded ? '↩ Restore' : '✕ Exclude';
        btn.title = f.excluded ? 'Re-include this event in the chain' : 'Exclude this event (false positive)';
        btn.addEventListener('click', (e) => { e.preventDefault(); this.toggleExclude(inc, f, card); });

        row.appendChild(sev); row.appendChild(name); row.appendChild(meta); row.appendChild(btn);

        const wrap = document.createElement('div');
        wrap.appendChild(row);
        if (f.commandline) {
            const cmd = document.createElement('div');
            cmd.className = 'inc-finding-cmd' + (f.excluded ? ' inc-finding-excluded' : '');
            cmd.textContent = f.commandline;
            wrap.appendChild(cmd);
        }
        return wrap;
    },

    async toggleExclude(inc, f, card) {
        const newExcluded = !f.excluded;
        try {
            const resp = await fetch('/api/triage/finding', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    incident_id: inc.id, finding_key: f.key, excluded: newExcluded,
                    suggested_priority: inc.suggested_priority,
                }),
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || `Server error (${resp.status})`);
            // Update local model: mark finding + recompute active severity, then re-render this card.
            f.excluded = newExcluded;
            inc.triage = inc.triage || {};
            inc.triage.excluded_findings = data.excluded_findings || [];
            this._recomputeActive(inc);
            const fresh = this.renderCard(inc);
            card.replaceWith(fresh);
            this.renderSummary();
        } catch (err) {
            if (window.BlueHound) BlueHound._showToast('Exclude failed: ' + err.message, 'error');
        }
    },

    // Mirror of backend triage.recompute_active so the card updates without a reload.
    _recomputeActive(inc) {
        const rank = { critical: 4, high: 3, medium: 2, low: 1, benign: 0 };
        const activeFindings = (inc.findings || []).filter(f => !f.excluded);
        inc.active_finding_count = activeFindings.length;
        inc.all_excluded = activeFindings.length === 0 && (inc.findings || []).length > 0;
        if (activeFindings.length) {
            let best = 'low';
            activeFindings.forEach(f => {
                const s = (f.severity || '').toLowerCase();
                if ((rank[s] || 0) > (rank[best] || 0)) best = s;
            });
            inc.severity = best.toUpperCase();
            const map = { CRITICAL: 'P0', HIGH: 'P1', MEDIUM: 'P2', LOW: 'P3' };
            inc.suggested_priority = map[inc.severity] || 'P3';
        }
    },

    async saveTriage(inc, card) {
        const status = this._statusToken(card.querySelector('.triage-status').value);
        const priority = this._prioToken(card.querySelector('.triage-priority').value);
        const note = card.querySelector('.triage-note').value;
        const btn = card.querySelector('.triage-save');
        const saved = card.querySelector('.triage-saved');
        btn.disabled = true;
        try {
            const resp = await fetch('/api/triage', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ incident_id: inc.id, status, priority, note }),
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || `Server error (${resp.status})`);
            // Update local state so summary + filter reflect the new triage immediately.
            inc.triage = { ...(inc.triage || {}), status, priority, note,
                           analyst: data.triage?.analyst || '', updated_at: data.triage?.updated_at || '' };
            saved.style.display = 'inline';
            setTimeout(() => { saved.style.display = 'none'; }, 1500);
            this.renderSummary();
            // Re-render card (status pill / closed styling) and re-apply filter.
            this.renderList();
        } catch (err) {
            if (window.BlueHound) BlueHound._showToast('Triage save failed: ' + err.message, 'error');
        } finally {
            btn.disabled = false;
        }
    },

    esc(s) {
        if (s === 0) return '0';
        return (window.BHUtils ? BHUtils.esc(s) : (s == null ? '' : String(s)));
    },
};
