/* =================================================================
   BlueHound -- LLM Panel (Session Summary + Event Analyzer)
   ================================================================= */

// VULN-16: Shared MITRE ID validator -- prevent open redirect via window.open()
const _LLM_MITRE_ID_RE = /^T\d{4}(\.\d{3})?$/;
function _llmSafeMitreUrl(id) {
    if (!_LLM_MITRE_ID_RE.test(String(id))) return null;
    return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';
}


const LLMPanel = {
    events:   [],
    findings: [],
    prescan: null,

    init(events, findings, prescan) {
        this.events   = events   || [];
        this.findings = findings || [];
        this.prescan  = prescan  || null;
        if (!this._bound) this.bindEvents();
        this.loadQuickPicks();
        this.renderPrescan();
        // Auto-generate AI summary when findings are available
        if (this.findings && this.findings.length > 0) {
            this.generateSummary();
        }
    },

    // showGenerateButton removed — summary is now auto-generated on init

    bindEvents() {
        this._bound = true;
        document.getElementById('llm-analyze-btn').addEventListener('click', () => this.analyze());
        document.getElementById('llm-cmdline-input').addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter') this.analyze();
        });
        const regenBtn = document.getElementById('llm-regen-summary-btn');
        if (regenBtn) regenBtn.addEventListener('click', () => this.generateSummary());

        // Toggle summary expand/collapse — entire header bar is clickable
        const toggleBtn = document.getElementById('llm-sum-toggle-btn');
        const strip = document.getElementById('llm-summary-section');
        const sumHeader = strip?.querySelector('.llm-sum-header');
        const fsBtn = document.getElementById('llm-sum-fullscreen-btn');
        if (toggleBtn && strip && sumHeader) {
            const doToggle = (e) => {
                // Ignore clicks that originated on action buttons
                if (e && e.target.closest('.llm-sum-actions')) return;
                strip.classList.toggle('expanded');
                toggleBtn.classList.toggle('rotated');
            };
            sumHeader.addEventListener('click', doToggle);
            toggleBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                strip.classList.toggle('expanded');
                toggleBtn.classList.toggle('rotated');
            });
            const regenBtnInner = document.getElementById('llm-regen-summary-btn');
            if (regenBtnInner) regenBtnInner.addEventListener('click', e => e.stopPropagation());
        }
        // Fullscreen toggle for the summary strip
        if (fsBtn && strip) {
            fsBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                const goingFullscreen = !strip.classList.contains('fullscreen');
                strip.classList.toggle('fullscreen');
                // Ensure body is visible when entering fullscreen
                if (goingFullscreen) {
                    strip.classList.add('expanded');
                    if (toggleBtn) toggleBtn.classList.add('rotated');
                }
            });
            // ESC exits fullscreen
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && strip.classList.contains('fullscreen')) {
                    strip.classList.remove('fullscreen');
                }
            });
        }

        // Mode tabs: Event Analyzer ⇄ NL Hunt (NL Hunt merged into this panel).
        this.bindModeTabs();

        // Clear button
        const clearBtn = document.getElementById('llm-clear-btn');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                document.getElementById('llm-cmdline-input').value = '';
                ['llm-ctx-eventid','llm-ctx-process','llm-ctx-host','llm-ctx-user'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) el.value = '';
                });
                document.getElementById('llm-result').innerHTML = `
                    <div class="llm-right-placeholder">
                        <div class="llm-placeholder-icon">🔍</div>
                        <p>Paste a command line and click <strong>Analyze</strong>,<br>or click any event in the Timeline / Graph.</p>
                    </div>`;
            });
        }
    },

    // Toggle between Event Analyzer and NL Hunt modes inside this panel.
    bindModeTabs() {
        const tabs = Array.from(document.querySelectorAll('.llm-mode-tab'));
        if (!tabs.length) return;
        const setMode = (mode) => {
            tabs.forEach(t => t.classList.toggle('active', t.dataset.mode === mode));
            document.querySelectorAll('.llm-mode-pane').forEach(p => {
                p.classList.toggle('hidden', p.dataset.mode !== mode);
            });
            if (mode === 'hunt') {
                const inp = document.getElementById('nlhunt-input');
                if (inp) inp.focus();
            }
        };
        tabs.forEach(t => t.addEventListener('click', () => setMode(t.dataset.mode)));
    },

    loadQuickPicks() {
        const container = document.getElementById('llm-quick-picks');
        container.innerHTML = '<h4>Quick Picks from Loaded Data</h4>';
        const seen = new Set();
        const interesting = this.events.filter(ev => {
            const cmd = ev.commandline || '';
            if (!cmd || cmd.length < 20 || seen.has(cmd)) return false;
            seen.add(cmd);
            return true;
        }).slice(0, 6);
        interesting.forEach(ev => {
            const item = document.createElement('div');
            item.className = 'quick-pick';
            item.textContent = (ev.commandline || '').substring(0, 90) + (ev.commandline && ev.commandline.length > 90 ? '…' : '');
            item.title = ev.commandline;
            item.addEventListener('click', () => {
                document.getElementById('llm-cmdline-input').value = ev.commandline;
                document.getElementById('llm-ctx-eventid').value  = ev.event_id  || '';
                document.getElementById('llm-ctx-process').value  = ev.process_name || '';
                document.getElementById('llm-ctx-host').value     = ev.hostname   || '';
                document.getElementById('llm-ctx-user').value     = ev.user_name  || '';
                this.analyze();
            });
            container.appendChild(item);
        });
    },

    // ── Session Summary ─────────────────────────────────────
    async generateSummary() {
        if (!this.findings || this.findings.length === 0) {
            this.renderPrescan();
            return;
        }
        // Auto-expand summary section so user sees the loading/result
        const section = document.getElementById('llm-summary-section');
        const toggleBtn = document.getElementById('llm-sum-toggle-btn');
        if (section && !section.classList.contains('expanded')) {
            section.classList.add('expanded');
            if (toggleBtn) toggleBtn.classList.add('rotated');
        }

        const summaryDiv = document.getElementById('llm-summary-result');
        summaryDiv.innerHTML = '<p style="color:var(--text-secondary);font-size:13px;">⏳ Generating threat summary…</p>';
        try {
            const resp = await fetch('/api/llm/summarize', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    events: this.events.slice(0, 500),
                    findings: this.findings.slice(0, 500),
                }),
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || `Server error (${resp.status})`);
            // Cache the most recent LLM summary so the PDF export can embed it.
            this.lastSummary = data;
            this.renderSummary(data);
        } catch (err) {
            summaryDiv.innerHTML = `<p style="color:var(--critical);">Error: ${this.esc(err.message)}</p>`;
        }
    },

    renderPrescan() {
        const div = document.getElementById('llm-summary-result');
        if (!div || !this.prescan) return;
        const report = this.prescan.report || {};
        const exec = this.prescan.execute || {};
        const scope = this.prescan.scope || {};
        const sev = (report.overall_severity || 'clean').toLowerCase();
        const sevColor = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', clean:'#22c55e' }[sev] || '#94a3b8';
        const hits = (exec.initial_findings || []).slice(0, 5);
        const phases = (exec.attack_phases || []).slice(0, 6);
        const nextSteps = (report.next_steps || []).slice(0, 5);
        const hitHtml = hits.length
            ? '<ul class="summary-findings-list">' + hits.map(h => {
                const indicators = (h.indicators || []).slice(0, 3).join(', ');
                return `<li>${this.esc(h.timestamp || '')} ${this.esc(h.hostname || '')} ${this.esc(h.process_name || '')}: ${this.esc(indicators || h.activity || '')}</li>`;
            }).join('') + '</ul>'
            : '<p style="color:var(--text-muted);font-size:12px;">No high-confidence malicious semantic indicators in the bounded pre-scan.</p>';
        const phaseHtml = phases.map(p => `<span class="summary-tag">${this.esc(p)}</span>`).join('');
        const stepHtml = nextSteps.map((s, i) =>
            `<div class="summary-action"><span class="action-num">${i + 1}</span>${this.esc(s)}</div>`
        ).join('');

        div.innerHTML = `
            <div class="summary-card">
                <div class="summary-top">
                    <div class="summary-sev-badge" style="background:${sevColor}20;border:1px solid ${sevColor};color:${sevColor};">
                        ${this.esc(sev.toUpperCase())}
                    </div>
                    <div>
                        <div style="font-size:15px;font-weight:700;">Initial LLM Hunt Pipeline</div>
                        <div style="font-size:11px;color:var(--text-muted);">
                            ${this.esc(this.prescan.framework || '')} &middot;
                            ${this.esc(scope.events_prescanned || 0)} / ${this.esc(scope.events_received || 0)} events
                            ${scope.truncated ? '&middot; bounded sample' : ''}
                        </div>
                    </div>
                </div>
                <div class="summary-narrative">
                    <div class="summary-section-label">Attack Phases</div>
                    <div>${phaseHtml}</div>
                </div>
                <div class="summary-findings">
                    <div class="summary-section-label">Pre-scan Findings</div>
                    ${hitHtml}
                </div>
                ${stepHtml ? `<div class="summary-actions"><div class="summary-section-label">Next Steps</div>${stepHtml}</div>` : ''}
            </div>`;
    },

    renderSummary(data) {
        const div = document.getElementById('llm-summary-result');
        if (!data || data.error) {
            div.innerHTML = `<p style="color:var(--text-muted);">Could not generate summary.</p>`;
            return;
        }
        const sevColor = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', clean:'#22c55e' };
        const sev = (data.overall_severity || 'clean').toLowerCase();
        const color = sevColor[sev] || '#94a3b8';
        const src = data.source === 'llm' ? '🤖 AI' : '📋 Heuristic';

        const hostsHtml   = (data.affected_hosts  || []).map(h => `<span class="summary-tag host-tag">${this.esc(h)}</span>`).join('');
        const usersHtml   = (data.affected_users  || []).map(u => `<span class="summary-tag user-tag">${this.esc(u)}</span>`).join('');
        const techHtml    = (data.techniques_used || [])
            .filter(t => t && t.id && _LLM_MITRE_ID_RE.test(String(t.id)))
            .map(t => {
                // VULN-16: no inline onclick -- use data-url for safe post-render binding
                const url = _llmSafeMitreUrl(t.id);
                return `<span class="detail-mitre-tag _llm-mitre" data-url="${url ? this.esc(url) : ''}" style="cursor:pointer">${this.esc(t.id)} ${this.esc(t.name)}</span>`;
            }).join('');
        const findHtml    = (data.key_findings    || []).map(f => `<li>${this.esc(f)}</li>`).join('');
        const actionsHtml = (data.immediate_actions || []).map((a,i) =>
            `<div class="summary-action"><span class="action-num">${i+1}</span>${this.esc(a)}</div>`
        ).join('');

        div.innerHTML = `
            <div class="summary-card">
                <div class="summary-top">
                    <div class="summary-sev-badge" style="background:${color}20;border:1px solid ${color};color:${color};">
                        ${sev.toUpperCase()}
                    </div>
                    <div>
                        <div style="font-size:15px;font-weight:700;">${this.esc(data.attack_stage || '')}</div>
                        <div style="font-size:11px;color:var(--text-muted);">Source: ${src} &middot; ${this.esc(data.threat_actor_profile || '')}</div>
                    </div>
                </div>

                <div class="summary-exec">
                    <p>${this.esc(data.executive_summary || '')}</p>
                </div>

                ${data.attack_narrative ? `
                <div class="summary-narrative">
                    <div class="summary-section-label">Attack Narrative</div>
                    <p>${this.esc(data.attack_narrative)}</p>
                </div>` : ''}

                <div class="summary-tags-row">
                    ${hostsHtml ? `<div><div class="summary-section-label">Affected Hosts</div>${hostsHtml}</div>` : ''}
                    ${usersHtml ? `<div><div class="summary-section-label">Affected Users</div>${usersHtml}</div>` : ''}
                </div>

                ${techHtml ? `<div class="summary-section-label" style="margin-top:10px;">MITRE Techniques</div><div>${techHtml}</div>` : ''}

                ${findHtml ? `
                <div class="summary-findings">
                    <div class="summary-section-label">Key Findings</div>
                    <ul class="summary-findings-list">${findHtml}</ul>
                </div>` : ''}

                ${actionsHtml ? `
                <div class="summary-actions">
                    <div class="summary-section-label">⚡ Immediate Actions</div>
                    ${actionsHtml}
                </div>` : ''}
            </div>`;

        // VULN-16: bind MITRE tag clicks safely after innerHTML is set
        div.querySelectorAll('._llm-mitre[data-url]').forEach(el => {
            const url = el.getAttribute('data-url');
            if (url) el.addEventListener('click', () => window.open(url, '_blank', 'noopener,noreferrer'));
        });
    },

    // ── Event Analyzer ───────────────────────────────────────
    async analyze(context) {
        let cmdline, eventCtx = {};
        if (!context || typeof context === 'undefined') {
            cmdline = document.getElementById('llm-cmdline-input').value.trim();
            // Read context fields from the UI
            eventCtx = {
                event_id:      document.getElementById('llm-ctx-eventid')?.value.trim() || null,
                process_name:  document.getElementById('llm-ctx-process')?.value.trim() || null,
                hostname:      document.getElementById('llm-ctx-host')?.value.trim()    || null,
                user_name:     document.getElementById('llm-ctx-user')?.value.trim()    || null,
                matched_rules: [],
            };
        } else if (typeof context === 'string') {
            cmdline = context;
        } else {
            cmdline  = context.commandline || '';
            eventCtx = {
                event_id:      context.event_id      || null,
                process_name:  context.process_name  || null,
                hostname:      context.hostname       || null,
                user_name:     context.user_name      || null,
                matched_rules: context.matched_rules  || [],
                properties:    context.properties     || null,
            };
            // Fill UI context fields
            if (context.event_id)     document.getElementById('llm-ctx-eventid').value = context.event_id;
            if (context.process_name) document.getElementById('llm-ctx-process').value  = context.process_name;
            if (context.hostname)     document.getElementById('llm-ctx-host').value     = context.hostname;
            if (context.user_name)    document.getElementById('llm-ctx-user').value     = context.user_name;
        }

        const inputEl = document.getElementById('llm-cmdline-input');
        if (inputEl && !inputEl.value.trim() && cmdline) inputEl.value = cmdline;
        if (!cmdline) return;

        const resultDiv = document.getElementById('llm-result');
        resultDiv.innerHTML = '<div class="llm-result-card"><p style="color:var(--text-secondary);">⏳ Analyzing…</p></div>';

        try {
            const resp = await fetch('/api/llm/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ commandline: cmdline, event_context: eventCtx }),
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || `Server error (${resp.status})`);
            this.renderResult(data, cmdline, eventCtx);
        } catch (err) {
            resultDiv.innerHTML = `<div class="llm-result-card"><p style="color:var(--critical);">Error: ${this.esc(err.message)}</p></div>`;
        }
    },

    analyzeFromGraph(cmdlineOrCtx) {
        BlueHound.switchPanel('llm');
        const cmdline = typeof cmdlineOrCtx === 'string' ? cmdlineOrCtx : (cmdlineOrCtx.commandline || '');
        document.getElementById('llm-cmdline-input').value = cmdline;
        setTimeout(() => this.analyze(cmdlineOrCtx), 100);
    },

    renderResult(data, cmdline, ctx) {
        const resultDiv = document.getElementById('llm-result');
        const sev = data.severity || 1;
        const isMalicious = data.is_malicious;
        let ringColor, ringBg;
        if (sev >= 9)      { ringColor = '#ef4444'; ringBg = 'rgba(239,68,68,0.15)'; }
        else if (sev >= 7) { ringColor = '#f97316'; ringBg = 'rgba(249,115,22,0.15)'; }
        else if (sev >= 5) { ringColor = '#eab308'; ringBg = 'rgba(234,179,8,0.15)'; }
        else               { ringColor = '#22c55e'; ringBg = 'rgba(34,197,94,0.15)'; }

        const mitreHtml = (data.mitre_techniques || [])
            .filter(t => _LLM_MITRE_ID_RE.test(String(t)))  // VULN-16: validate before use
            .map(t => {
                const url = _llmSafeMitreUrl(t);
                return `<span class="detail-mitre-tag _llm-mitre" data-url="${url ? this.esc(url) : ''}" style="cursor:pointer">${this.esc(String(t))}</span>`;
            }).join(' ');

        const indicHtml = (data.indicators || []).length
            ? '<ul>' + (data.indicators).map(i => `<li>${this.esc(i)}</li>`).join('') + '</ul>' : '';

        // Context badge row
        const ctxParts = [];
        if (ctx?.event_id)     ctxParts.push(`EID ${ctx.event_id}`);
        if (ctx?.process_name) ctxParts.push(ctx.process_name);
        if (ctx?.hostname)     ctxParts.push(ctx.hostname);
        if (ctx?.user_name)    ctxParts.push(ctx.user_name);
        const ctxBadge = ctxParts.length
            ? `<div style="margin-bottom:8px;font-size:11px;color:var(--text-muted);">${ctxParts.map(p => `<span style="background:var(--surface-2);padding:2px 6px;border-radius:3px;margin-right:4px;">${this.esc(p)}</span>`).join('')}</div>`
            : '';

        resultDiv.innerHTML = `
            <div class="llm-result-card">
                ${ctxBadge}
                <div class="llm-result-header">
                    <div class="llm-severity-ring" style="border:3px solid ${ringColor};background:${ringBg};color:${ringColor};">${sev}</div>
                    <div>
                        <div style="font-size:18px;font-weight:700;color:${isMalicious ? '#ef4444' : '#22c55e'}">
                            ${isMalicious ? '⚠ MALICIOUS' : '✓ BENIGN'}
                        </div>
                        <div style="font-size:12px;color:var(--text-muted)">Source: ${this.esc(data.source || 'unknown')}</div>
                    </div>
                </div>

                <div class="llm-result-section">
                    <h4>Intent Analysis</h4>
                    <p>${this.esc(data.intent || 'No analysis available.')}</p>
                </div>

                ${data.decoded ? `
                <div class="llm-result-section">
                    <h4>Decoded Command</h4>
                    <div class="llm-decoded">${this.esc(data.decoded)}</div>
                </div>` : ''}

                ${mitreHtml ? `
                <div class="llm-result-section">
                    <h4>MITRE ATT&CK Techniques</h4>
                    <div>${mitreHtml}</div>
                </div>` : ''}

                ${indicHtml ? `
                <div class="llm-result-section">
                    <h4>Indicators</h4>
                    ${indicHtml}
                </div>` : ''}

                <div class="llm-result-section">
                    <h4>Recommendation</h4>
                    <p>${this.esc(data.recommendation || '')}</p>
                </div>
            </div>

            <div class="llm-result-card" style="border-left:3px solid var(--border-active);">
                <div class="llm-result-section">
                    <h4>Analyzed Input</h4>
                    <div class="llm-decoded">${this.esc(cmdline)}</div>
                </div>
            </div>`;

        // VULN-16: bind MITRE tag clicks safely after innerHTML is set
        resultDiv.querySelectorAll('._llm-mitre[data-url]').forEach(el => {
            const url = el.getAttribute('data-url');
            if (url) el.addEventListener('click', () => window.open(url, '_blank', 'noopener,noreferrer'));
        });

        // FR-4: fetch + render the embedding similarity signal for this command.
        this.renderSimilarity(cmdline, resultDiv);

        // FR-5: analyst verdict feedback (agree/disagree → /api/feedback).
        this.renderFeedback(cmdline, ctx, data, resultDiv);
    },

    // FR-4: embedding similarity intelligence, rendered into the result card.
    async renderSimilarity(cmdline, resultDiv) {
        const firstCard = resultDiv.querySelector('.llm-result-card');
        if (!firstCard) return;
        const section = document.createElement('div');
        section.className = 'llm-result-section';
        const h = document.createElement('h4');
        h.textContent = 'Similarity Intelligence (embedding)';
        const body = document.createElement('div');
        body.className = 'llm-sim-body';
        body.textContent = '⏳ comparing to known-bad corpus…';
        section.appendChild(h); section.appendChild(body);
        firstCard.appendChild(section);
        try {
            const resp = await fetch('/api/llm/similar', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ commandline: cmdline, k: 3 }),
            });
            const d = await resp.json();
            if (!resp.ok) throw new Error(d.error || `Server error (${resp.status})`);
            body.innerHTML = '';
            const flag = document.createElement('div');
            const c = d.similar_to_known_bad ? '#ef4444' : '#22c55e';
            flag.className = 'llm-sim-flag'; flag.style.color = c;
            flag.textContent = d.similar_to_known_bad
                ? `⚠ Resembles known-bad (${d.cluster_id}) — score ${d.max_known_bad_score}`
                : `✓ No strong resemblance to known-bad (score ${d.max_known_bad_score})`;
            body.appendChild(flag);
            const meta = document.createElement('div');
            meta.className = 'llm-sim-meta';
            meta.textContent = `novelty ${d.novelty} · source ${d.source} · ${d.model_id}`;
            body.appendChild(meta);
            (d.neighbors || []).forEach(n => {
                const row = document.createElement('div');
                row.className = 'llm-sim-row';
                row.textContent = `${n.label} · ${n.score}`;
                body.appendChild(row);
            });
        } catch (err) {
            body.textContent = 'Similarity unavailable: ' + err.message;
        }
    },

    // FR-5: analyst verdict feedback. All DOM-API built (no innerHTML w/ user data).
    renderFeedback(cmdline, ctx, data, resultDiv) {
        const firstCard = resultDiv.querySelector('.llm-result-card');
        if (!firstCard) return;
        const section = document.createElement('div');
        section.className = 'llm-result-section llm-feedback';
        const h = document.createElement('h4');
        h.textContent = 'Was this verdict correct?';
        section.appendChild(h);

        const row = document.createElement('div');
        row.className = 'llm-fb-row';

        const analystInput = document.createElement('input');
        analystInput.type = 'text';
        analystInput.placeholder = 'analyst';
        analystInput.className = 'llm-ctx-input';
        analystInput.classList.add('llm-fb-analyst');
        // localStorage can throw (private mode / blocked / opaque origin) — guard it.
        try { analystInput.value = localStorage.getItem('bh_analyst') || ''; } catch (_) { analystInput.value = ''; }

        const agreeBtn = document.createElement('button');
        agreeBtn.className = 'btn-secondary';
        agreeBtn.style.fontSize = '12px';
        agreeBtn.textContent = '✓ Agree';

        const disagreeBtn = document.createElement('button');
        disagreeBtn.className = 'btn-ghost';
        disagreeBtn.style.fontSize = '12px';
        disagreeBtn.textContent = '✗ Disagree';

        const status = document.createElement('span');
        status.className = 'llm-fb-status';

        const llmVerdict = { is_malicious: !!data.is_malicious, severity: data.severity || 1 };
        const analyst = () => (analystInput.value.trim() || 'analyst');
        const remember = () => { try { localStorage.setItem('bh_analyst', analyst()); } catch (_) {} };

        const submit = async (body) => {
            remember();
            status.textContent = '⏳ saving…';
            try {
                const resp = await fetch('/api/feedback', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ commandline: cmdline, context: ctx || {},
                        analyst: analyst(), llm_verdict: llmVerdict, ...body }),
                });
                const d = await resp.json();
                if (!resp.ok) throw new Error(d.error || `Server error (${resp.status})`);
                status.textContent = `✓ recorded (trust ${d.trust})`;
                agreeBtn.disabled = disagreeBtn.disabled = true;
            } catch (err) {
                status.textContent = 'Save failed: ' + err.message;
            }
        };

        agreeBtn.addEventListener('click', () => submit({ agree: true }));
        disagreeBtn.addEventListener('click', () => {
            // Reveal a correction form: corrected verdict + severity.
            corr.classList.add('show');
        });

        row.appendChild(analystInput);
        row.appendChild(agreeBtn);
        row.appendChild(disagreeBtn);
        row.appendChild(status);
        section.appendChild(row);

        // Correction form (hidden until Disagree)
        const corr = document.createElement('div');
        corr.className = 'llm-fb-corr';
        const verdictSel = document.createElement('select');
        verdictSel.className = 'llm-ctx-input'; verdictSel.style.maxWidth = '130px';
        [['true', 'Malicious'], ['false', 'Benign']].forEach(([v, label]) => {
            const o = document.createElement('option'); o.value = v; o.textContent = label;
            verdictSel.appendChild(o);
        });
        verdictSel.value = data.is_malicious ? 'false' : 'true';  // default to the opposite (they disagreed)
        const sevSel = document.createElement('select');
        sevSel.className = 'llm-ctx-input'; sevSel.style.maxWidth = '90px';
        for (let i = 1; i <= 10; i++) { const o = document.createElement('option'); o.value = i; o.textContent = 'sev ' + i; sevSel.appendChild(o); }
        sevSel.value = String(data.severity || 5);
        const sendCorr = document.createElement('button');
        sendCorr.className = 'btn-primary'; sendCorr.style.fontSize = '12px'; sendCorr.textContent = 'Submit correction';
        sendCorr.addEventListener('click', () => submit({
            agree: false,
            corrected_is_malicious: verdictSel.value === 'true',
            corrected_severity: parseInt(sevSel.value, 10),
        }));
        corr.appendChild(verdictSel); corr.appendChild(sevSel); corr.appendChild(sendCorr);
        section.appendChild(corr);

        firstCard.appendChild(section);
    },

    esc(s) {
        return (window.BHUtils ? BHUtils.esc(s) : (s == null ? '' : String(s)));
    }
};
