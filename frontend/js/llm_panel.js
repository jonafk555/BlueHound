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

    init(events, findings) {
        this.events   = events   || [];
        this.findings = findings || [];
        this.bindEvents();
        this.loadQuickPicks();
        // Auto-generate summary when data loaded
        this.generateSummary();
    },

    bindEvents() {
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
        if (toggleBtn && strip && sumHeader) {
            const doToggle = () => {
                strip.classList.toggle('expanded');
                toggleBtn.classList.toggle('rotated');
            };
            sumHeader.addEventListener('click', doToggle);
            // Prevent Re-generate button from also toggling
            const regenBtnInner = document.getElementById('llm-regen-summary-btn');
            if (regenBtnInner) regenBtnInner.addEventListener('click', e => e.stopPropagation());
        }

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
        if (!this.findings || this.findings.length === 0) return;
        const summaryDiv = document.getElementById('llm-summary-result');
        summaryDiv.innerHTML = '<p style="color:var(--text-secondary);font-size:13px;">⏳ Generating threat summary…</p>';
        try {
            const resp = await fetch('/api/llm/summarize', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ events: this.events, findings: this.findings }),
            });
            const data = await resp.json();
            this.renderSummary(data);
        } catch (err) {
            summaryDiv.innerHTML = `<p style="color:var(--critical);">Error: ${err.message}</p>`;
        }
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
            this.renderResult(data, cmdline, eventCtx);
        } catch (err) {
            resultDiv.innerHTML = `<div class="llm-result-card"><p style="color:var(--critical);">Error: ${err.message}</p></div>`;
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
    },

    esc(s) {
        if (!s) return '';
        const d = document.createElement('div');
        d.textContent = String(s);
        return d.innerHTML;
    }
};
