/* ═══════════════════════════════════════════════════════════
   BlueHound — Threat Hunt Findings Panel
   ═══════════════════════════════════════════════════════════ */

const HuntPanel = {
    findings: [],

    render(findings) {
        this.findings = findings || [];
        this.renderSummary();
        this.renderFindings();
    },

    renderSummary() {
        const container = document.getElementById('hunt-summary');
        container.innerHTML = '';

        // Count by severity (case-insensitive)
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        const tactics = {};
        const techniques = {};

        this.findings.forEach(f => {
            const s = (f.severity || '').toLowerCase();
            if (counts[s] !== undefined) counts[s]++;
            if (f.tactic) tactics[f.tactic] = (tactics[f.tactic] || 0) + 1;
            if (f.mitre) techniques[f.mitre] = (techniques[f.mitre] || 0) + 1;
        });

        // Cards
        const cards = [
            { label: 'Total Findings', value: this.findings.length, cls: '' },
            { label: 'Critical', value: counts.critical, cls: 'critical' },
            { label: 'High', value: counts.high, cls: 'high' },
            { label: 'Medium', value: counts.medium, cls: 'medium' },
            { label: 'Unique Techniques', value: Object.keys(techniques).length, cls: '' },
            { label: 'ATT&CK Tactics', value: Object.keys(tactics).length, cls: '' },
        ];

        cards.forEach(c => {
            const card = document.createElement('div');
            card.className = 'hunt-card';
            // c.label and c.value are hardcoded constants — safe to use directly
            card.innerHTML = `
                <div class="hunt-card-title">${c.label}</div>
                <div class="hunt-card-value ${c.cls}">${c.value}</div>
            `;
            container.appendChild(card);
        });

        // Tactic breakdown cards — tactic names come from log data, must be escaped
        Object.entries(tactics).sort((a, b) => b[1] - a[1]).forEach(([tactic, count]) => {
            const card = document.createElement('div');
            card.className = 'hunt-card';
            card.innerHTML = `
                <div class="hunt-card-title">${this.escapeHtml(tactic)}</div>
                <div class="hunt-card-value">${Number(count)}</div>
            `;
            container.appendChild(card);
        });
    },

    renderFindings() {
        const container = document.getElementById('hunt-findings');
        container.innerHTML = '<h2 style="margin-bottom:16px;font-size:18px;">Findings</h2>';

        // Group by severity order
        const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        const sorted = [...this.findings].sort((a, b) => {
            return sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity);
        });

        sorted.forEach(f => {
            const item = document.createElement('div');
            item.className = 'finding-item';
            // VULN-09: ALL values from log data must be escaped before innerHTML insertion
            const sev    = this.escapeHtml((f.severity || '').toLowerCase());
            const mitre  = this.escapeHtml(f.mitre || '');
            const ts     = this.escapeHtml((f.timestamp || '').replace('T', ' ').replace('Z', ''));
            const cmdHtml = f.commandline
                ? `<div class="finding-cmdline">${this.escapeHtml(f.commandline)}</div>`
                : '';
            item.innerHTML = `
                <div class="finding-header">
                    <span class="finding-sev ${sev}">${sev.toUpperCase()}</span>
                    <span class="finding-name">${this.escapeHtml(f.rule_name)}</span>
                    <span class="finding-mitre">${mitre}</span>
                </div>
                <div class="finding-details">${this.escapeHtml(f.description)}</div>
                <div style="display:flex;gap:12px;font-size:12px;color:var(--text-muted);margin-bottom:6px;">
                    <span>⬤ ${this.escapeHtml(f.process_name || 'N/A')}</span>
                    <span>🖥 ${this.escapeHtml(f.hostname || 'N/A')}</span>
                    <span>👤 ${this.escapeHtml(f.user_name || 'N/A')}</span>
                    <span>🕐 ${ts}</span>
                </div>
                ${cmdHtml}
                <div class="finding-guidance">
                    <strong>Hunt Guidance:</strong> ${this.escapeHtml(f.hunt_guidance || '')}
                </div>
            `;
            item.addEventListener('click', () => item.classList.toggle('expanded'));
            container.appendChild(item);
        });
    },

    escapeHtml(s) {
        if (!s) return '';
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }
};
