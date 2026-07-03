/* ═══════════════════════════════════════════════════════════
   BlueHound — Threat Hunt Findings Panel
   ═══════════════════════════════════════════════════════════ */

const HuntPanel = {
    findings: [],
    activeFilter: null, // { kind: 'severity'|'tactic'|'all', value: string }

    render(findings) {
        this.findings = findings || [];
        this.activeFilter = null;
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

        // Cards — each carries a data filter so clicking narrows the list.
        const cards = [
            { label: 'Total Findings',    value: this.findings.length,            cls: '', filter: { kind: 'all' } },
            { label: 'Critical',          value: counts.critical,                 cls: 'critical', filter: { kind: 'severity', value: 'critical' } },
            { label: 'High',              value: counts.high,                     cls: 'high',     filter: { kind: 'severity', value: 'high' } },
            { label: 'Medium',            value: counts.medium,                   cls: 'medium',   filter: { kind: 'severity', value: 'medium' } },
            { label: 'Unique Techniques', value: Object.keys(techniques).length,  cls: '' /* not filterable */ },
            { label: 'ATT&CK Tactics',    value: Object.keys(tactics).length,     cls: '' /* not filterable */ },
        ];

        cards.forEach(c => {
            const card = document.createElement('div');
            card.className = 'hunt-card';
            if (c.filter) card.classList.add('hunt-card-clickable');
            card.innerHTML = `
                <div class="hunt-card-title">${c.label}</div>
                <div class="hunt-card-value ${c.cls}">${c.value}</div>
            `;
            if (c.filter) {
                card.addEventListener('click', () => this._toggleFilter(c.filter));
                if (this._matchesActive(c.filter)) card.classList.add('hunt-card-active');
            }
            container.appendChild(card);
        });

        // Tactic breakdown cards — clickable to filter by tactic.
        Object.entries(tactics).sort((a, b) => b[1] - a[1]).forEach(([tactic, count]) => {
            const card = document.createElement('div');
            card.className = 'hunt-card hunt-card-clickable';
            card.innerHTML = `
                <div class="hunt-card-title">${this.escapeHtml(tactic)}</div>
                <div class="hunt-card-value">${Number(count)}</div>
            `;
            const filter = { kind: 'tactic', value: tactic };
            if (this._matchesActive(filter)) card.classList.add('hunt-card-active');
            card.addEventListener('click', () => this._toggleFilter(filter));
            container.appendChild(card);
        });
    },

    _matchesActive(filter) {
        if (!this.activeFilter) return false;
        if (this.activeFilter.kind !== filter.kind) return false;
        if (filter.kind === 'all') return true;
        return this.activeFilter.value === filter.value;
    },

    _toggleFilter(filter) {
        // Clicking the same card again clears the filter.
        if (this._matchesActive(filter) || filter.kind === 'all') {
            this.activeFilter = null;
        } else {
            this.activeFilter = filter;
        }
        this.renderSummary();
        this.renderFindings();
    },

    _filteredFindings() {
        if (!this.activeFilter || this.activeFilter.kind === 'all') return this.findings;
        if (this.activeFilter.kind === 'severity') {
            return this.findings.filter(f => (f.severity || '').toLowerCase() === this.activeFilter.value);
        }
        if (this.activeFilter.kind === 'tactic') {
            return this.findings.filter(f => f.tactic === this.activeFilter.value);
        }
        return this.findings;
    },

    renderFindings() {
        const container = document.getElementById('hunt-findings');
        container.innerHTML = '';

        const heading = document.createElement('div');
        heading.className = 'findings-heading-row';
        const label = this.activeFilter
            ? (this.activeFilter.kind === 'severity'
                ? `Findings — ${this.activeFilter.value.toUpperCase()}`
                : `Findings — ${this.escapeHtml(this.activeFilter.value)}`)
            : 'Findings';
        heading.innerHTML = `<h2 style="margin:0;font-size:18px;">${label}</h2>`;
        if (this.activeFilter) {
            const clearBtn = document.createElement('button');
            clearBtn.className = 'hunt-clear-filter';
            clearBtn.textContent = 'Clear filter ✕';
            clearBtn.addEventListener('click', () => {
                this.activeFilter = null;
                this.renderSummary();
                this.renderFindings();
            });
            heading.appendChild(clearBtn);
        }
        container.appendChild(heading);

        const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        const sorted = [...this._filteredFindings()].sort((a, b) => {
            return sevOrder.indexOf((a.severity || '').toUpperCase()) - sevOrder.indexOf((b.severity || '').toUpperCase());
        });

        if (sorted.length === 0) {
            const empty = document.createElement('p');
            empty.style.cssText = 'color:var(--text-muted);font-size:13px;padding:10px 0;';
            empty.textContent = 'No findings match the selected filter.';
            container.appendChild(empty);
            return;
        }

        sorted.forEach(f => {
            const item = document.createElement('div');
            item.className = 'finding-item';
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
        return (window.BHUtils ? BHUtils.esc(s) : (s == null ? '' : String(s)));
    }
};
