/* ═══════════════════════════════════════════════════════════
   BlueHound — Hunt Hypotheses Board (FR-2)
   Ranked, grounded *suspected* hypotheses (risks NOT already rule-confirmed)
   with one-click validation queries (reuses the FR-1 IR executor).
   Styling via design-system CSS classes (not inline). XSS-safe: textContent.
   ═══════════════════════════════════════════════════════════ */

const HypothesesPanel = {
    sessionId: null,
    hypotheses: [],
    generatedFor: null,
    busy: false,

    STATUS: { untested: '⬜ Untested', confirmed: '✅ Confirmed', refuted: '❌ Refuted' },

    init(sessionId) {
        this.sessionId = sessionId || null;
        this.hypotheses = [];
        this.generatedFor = null;
        if (!this._bound) {
            const btn = document.getElementById('hyp-generate-btn');
            if (btn) btn.addEventListener('click', () => this.generate(true));
            this._bound = true;
        }
        this._placeholder('Click “Generate” to derive ranked, suspected hunt leads for this session.');
    },

    onShow() {
        if (this.sessionId && this.generatedFor !== this.sessionId && !this.busy) this.generate(false);
    },

    _placeholder(msg) {
        const list = document.getElementById('hyp-list');
        if (!list) return;
        list.innerHTML = '';
        const p = document.createElement('p');
        p.className = 'fr-placeholder';
        p.textContent = this.sessionId ? msg : 'Load a dataset first.';
        list.appendChild(p);
    },

    async generate(force) {
        if (this.busy || !this.sessionId) {
            if (!this.sessionId && window.BlueHound) BlueHound._showToast('Load a dataset first.', 'error');
            return;
        }
        this.busy = true;
        this._placeholder('⏳ Generating and validating suspected hypotheses…');
        try {
            const resp = await fetch('/api/llm/hypotheses', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: this.sessionId }),
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || `Server error (${resp.status})`);
            this.hypotheses = data.hypotheses || [];
            this.generatedFor = this.sessionId;
            this.render(data);
        } catch (err) {
            this._placeholder('Error: ' + err.message);
        } finally {
            this.busy = false;
        }
    },

    render(data) {
        const list = document.getElementById('hyp-list');
        if (!list) return;
        list.innerHTML = '';
        if (!this.hypotheses.length) {
            this._placeholder('No suspected leads — every flagged risk is already covered by an existing rule (see Threat Hunt / Incidents).');
            return;
        }
        const banner = document.createElement('div');
        banner.className = 'fr-banner';
        const src = { llm: '🤖 model', heuristic: '📋 heuristic', 'llm-skipped': '🛡 skipped (injection)' }[data.source] || data.source;
        banner.textContent = `${this.hypotheses.length} suspected hypotheses · ${src} · ${data.model_id || ''}`;
        list.appendChild(banner);
        this.hypotheses.forEach(h => list.appendChild(this.renderCard(h)));
    },

    _confColor(conf) {
        if (conf >= 0.8) return '#ef4444';
        if (conf >= 0.6) return '#f97316';
        if (conf >= 0.45) return '#eab308';
        return '#3b82f6';
    },

    renderCard(h) {
        const card = document.createElement('div');
        card.className = 'fr-card hyp-card';

        // ── Header: confidence + title ──
        const head = document.createElement('div');
        head.className = 'fr-card-head';
        const conf = document.createElement('div');
        conf.className = 'fr-conf';
        conf.style.color = this._confColor(h.confidence);
        const pct = Math.round((h.confidence || 0) * 100);
        conf.textContent = pct + '%';
        conf.setAttribute('role', 'img');
        conf.setAttribute('aria-label', `Confidence ${pct} percent`);
        const stmt = document.createElement('div');
        stmt.className = 'fr-title';
        stmt.textContent = h.hypothesis || '';
        head.appendChild(conf);
        head.appendChild(stmt);
        card.appendChild(head);

        // ── Categorised threat detail grid ──
        const grid = document.createElement('div');
        grid.className = 'hyp-detail-grid';

        const hosts = (h.entities && h.entities.hosts) || [];
        const users = (h.entities && h.entities.users) || [];
        const mitre = h.mitre || [];
        const tactics = this._tacticsForTechniques(mitre);
        const evidenceCount = Number(h.evidence_count) || 0;
        const evidenceSample = h.evidence_sample || [];
        const confLabel = this._confidenceBand(h.confidence);
        const kind = h.kind === 'suspected' ? 'Suspected (no rule match)'
                   : h.kind === 'confirmed' ? 'Confirmed'
                   : 'Untested';

        this._detailRow(grid, 'Hosts', hosts, 'host');
        this._detailRow(grid, 'Users / Accounts', users, 'user');
        this._detailRow(grid, 'MITRE ATT&CK', mitre, 'mitre', (id) => this._mitreLink(id));
        this._detailRow(grid, 'Tactics', tactics, 'tactic');
        this._detailRow(grid, 'Kind', [kind], 'kind-plain');
        this._detailRow(grid, 'Confidence Band', [confLabel], 'conf-plain');
        this._detailRow(grid, 'Supporting Evidence',
                        [`${evidenceCount} matching event(s)`], 'evidence-plain');
        card.appendChild(grid);

        // ── Rationale ──
        if (h.rationale) {
            const secR = document.createElement('div');
            secR.className = 'hyp-section';
            const lbl = document.createElement('div');
            lbl.className = 'hyp-section-label';
            lbl.textContent = 'Rationale';
            const body = document.createElement('div');
            body.className = 'hyp-section-body';
            body.textContent = h.rationale;
            secR.appendChild(lbl); secR.appendChild(body);
            card.appendChild(secR);
        }

        // ── Sample matching events (from validation query pre-run) ──
        if (evidenceSample.length > 0) {
            const secE = document.createElement('details');
            secE.className = 'hyp-section hyp-evidence';
            const sum = document.createElement('summary');
            sum.className = 'hyp-section-label';
            sum.textContent = `Sample events (${evidenceSample.length}/${evidenceCount})`;
            secE.appendChild(sum);
            evidenceSample.slice(0, 5).forEach(ev => {
                const row = document.createElement('div');
                row.className = 'hyp-evidence-row';
                const ts = ev.timestamp ? String(ev.timestamp).replace('T', ' ').replace('Z', '') : '—';
                const meta = document.createElement('div');
                meta.className = 'hyp-evidence-meta';
                meta.textContent = `${ts} · ${ev.hostname || '?'} · ${ev.user_name || '?'} · ${ev.process_name || ev.event_id || '?'}`;
                row.appendChild(meta);
                if (ev.commandline) {
                    const cmd = document.createElement('div');
                    cmd.className = 'hyp-evidence-cmd';
                    cmd.textContent = ev.commandline;
                    row.appendChild(cmd);
                }
                secE.appendChild(row);
            });
            card.appendChild(secE);
        }

        // ── Validation query (informational, collapsible) ──
        const det = document.createElement('details');
        det.className = 'fr-collapse';
        const sum2 = document.createElement('summary');
        sum2.className = 'fr-summary';
        sum2.textContent = 'Validation query (IR)';
        det.appendChild(sum2);
        det.appendChild(this._irSummary(h.validation_query));
        card.appendChild(det);

        // ── Status control (Run query removed — the executor already
        // computed evidence_count/evidence_sample at generation time, so a
        // manual re-run added no signal). ──
        const controls = document.createElement('div');
        controls.className = 'fr-controls';
        const statusLabel = document.createElement('label');
        statusLabel.className = 'hyp-status-label';
        statusLabel.textContent = 'Analyst status:';
        const sel = document.createElement('select');
        sel.className = 'fr-select';
        sel.setAttribute('aria-label', 'Hypothesis status');
        Object.entries(this.STATUS).forEach(([v, label]) => {
            const o = document.createElement('option');
            o.value = v; o.textContent = label;
            if (v === (h.status || 'untested')) o.selected = true;
            sel.appendChild(o);
        });
        sel.addEventListener('change', () => { h.status = sel.value; });
        statusLabel.appendChild(sel);
        controls.appendChild(statusLabel);
        card.appendChild(controls);

        return card;
    },

    // Render one labelled row of chips (or a plain string when no chips fit).
    _detailRow(grid, label, values, chipClass, buildChip) {
        const row = document.createElement('div');
        row.className = 'hyp-detail-row';
        const lbl = document.createElement('div');
        lbl.className = 'hyp-detail-label';
        lbl.textContent = label;
        row.appendChild(lbl);

        const val = document.createElement('div');
        val.className = 'hyp-detail-value';
        const list = (values || []).filter(v => v !== undefined && v !== null && String(v).length);
        if (list.length === 0) {
            const dash = document.createElement('span');
            dash.className = 'hyp-detail-none';
            dash.textContent = '—';
            val.appendChild(dash);
        } else if (chipClass.endsWith('-plain')) {
            val.textContent = list.join(', ');
        } else {
            list.forEach(item => {
                const chip = buildChip ? buildChip(item)
                                       : document.createElement('span');
                if (!buildChip) {
                    chip.className = 'hyp-chip hyp-chip-' + chipClass;
                    chip.textContent = String(item);
                }
                val.appendChild(chip);
            });
        }
        row.appendChild(val);
        grid.appendChild(row);
    },

    // Clickable MITRE link chip. XSS-safe: attribute + textContent only.
    _mitreLink(id) {
        const safeId = String(id || '').trim();
        const a = document.createElement('a');
        a.className = 'hyp-chip hyp-chip-mitre';
        a.textContent = safeId;
        // Only build a URL for the canonical Txxxx[.yyy] pattern.
        if (/^T\d{4}(\.\d{3})?$/.test(safeId)) {
            a.href = 'https://attack.mitre.org/techniques/' + safeId.replace('.', '/') + '/';
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
        }
        return a;
    },

    _confidenceBand(c) {
        const n = Number(c) || 0;
        if (n >= 0.8) return 'High';
        if (n >= 0.6) return 'Elevated';
        if (n >= 0.45) return 'Moderate';
        return 'Low';
    },

    _TACTIC_BY_TECH: {
        'T1003': 'Credential Access',
        'T1027': 'Defense Evasion',
        'T1047': 'Execution',
        'T1053': 'Persistence',
        'T1059': 'Execution',
        'T1110': 'Credential Access',
        'T1140': 'Defense Evasion',
        'T1197': 'Defense Evasion',
        'T1218': 'Defense Evasion',
        'T1543': 'Persistence',
        'T1547': 'Persistence',
        'T1562': 'Defense Evasion',
        'T1021': 'Lateral Movement',
    },

    _tacticsForTechniques(techs) {
        const set = new Set();
        (techs || []).forEach(t => {
            const base = String(t).split('.')[0];
            const tactic = this._TACTIC_BY_TECH[base];
            if (tactic) set.add(tactic);
        });
        return Array.from(set);
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
        return wrap;
    },
};
