/* ═══════════════════════════════════════════════════════════
   BlueHound — KQL / SPL / Sigma Query Builder
   ═══════════════════════════════════════════════════════════ */

const QueryPanel = {
    facets: {},
    findings: [],
    format: 'kql',

    init(facets, findings) {
        this.facets = facets || {};
        this.findings = findings || [];
        this.format = 'kql';
        this.buildFilters();
        this.bindEvents();
        this.loadSuggestions();
        // QA FIX: auto-generate initial query so box is never blank on open
        this.generate();
    },

    buildFilters() {
        const container = document.getElementById('query-filters');
        container.innerHTML = '';

        const filters = [
            { key: 'source_ip', label: 'Source IP', type: 'select', options: this.facets.source_ip || [] },
            { key: 'destination_ip', label: 'Destination IP', type: 'select', options: this.facets.destination_ip || [] },
            { key: 'process_name', label: 'Process Name', type: 'select', options: this.facets.process_name || [] },
            { key: 'hostname', label: 'Hostname', type: 'select', options: this.facets.hostname || [] },
            { key: 'user_name', label: 'User Name', type: 'select', options: this.facets.user_name || [] },
            { key: 'event_id', label: 'Event ID', type: 'select', options: this.facets.event_id || [] },
            { key: 'commandline_contains', label: 'CommandLine Contains', type: 'text' },
            { key: 'commandline_regex', label: 'CommandLine Regex', type: 'text' },
            { key: 'time_range', label: 'Time Range', type: 'select', options: ['1h', '4h', '12h', '24h', '7d', '30d'] },
        ];

        filters.forEach(f => {
            const group = document.createElement('div');
            group.className = 'filter-group';

            const label = document.createElement('label');
            label.className = 'filter-label';
            label.textContent = f.label;
            group.appendChild(label);

            if (f.type === 'select') {
                const select = document.createElement('select');
                select.className = 'filter-select';
                select.id = `filter-${f.key}`;
                // Safe "All" option
                const allOpt = document.createElement('option');
                allOpt.value = '';
                allOpt.textContent = '-- All --';
                select.appendChild(allOpt);
                // QA security: use DOM API instead of innerHTML for options (attacker-controlled facet values)
                f.options.forEach(opt => {
                    const o = document.createElement('option');
                    o.value = String(opt);
                    o.textContent = String(opt);
                    select.appendChild(o);
                });
                group.appendChild(select);
            } else {
                const input = document.createElement('input');
                input.type = 'text';
                input.className = 'filter-input';
                input.id = `filter-${f.key}`;
                input.placeholder = `Enter ${f.label.toLowerCase()}...`;
                group.appendChild(input);
            }

            container.appendChild(group);
        });
    },

    bindEvents() {
        // Format selector — switch format AND auto-regenerate query
        document.querySelectorAll('.fmt-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.fmt-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.format = btn.dataset.fmt;
                this.generate();  // QA BUG FIX: auto-regenerate on format switch
            });
        });

        // Generate button
        document.getElementById('generate-query-btn').addEventListener('click', () => this.generate());

        // Copy button
        document.getElementById('copy-query-btn').addEventListener('click', () => this.copyQuery());
    },

    getFilters() {
        const keys = ['source_ip', 'destination_ip', 'process_name', 'hostname',
                       'user_name', 'event_id', 'commandline_contains', 'commandline_regex', 'time_range'];
        const filters = {};
        keys.forEach(k => {
            const el = document.getElementById(`filter-${k}`);
            if (el && el.value) filters[k] = el.value;
        });
        return filters;
    },

    async generate() {
        const filters = this.getFilters();
        try {
            const resp = await fetch('/api/query/build', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filters, format: this.format }),
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || `Server error (${resp.status})`);
            document.getElementById('query-result').textContent = data.query || 'No query generated.';
        } catch (err) {
            document.getElementById('query-result').textContent = 'Error generating query: ' + err.message;
        }
    },

    copyQuery() {
        const text = document.getElementById('query-result').textContent;
        navigator.clipboard.writeText(text).then(() => {
            const btn = document.getElementById('copy-query-btn');
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.textContent = 'Copy';
                btn.classList.remove('copied');
            }, 2000);
        });
    },

    loadSuggestions() {
        const container = document.getElementById('query-suggestions');
        container.innerHTML = '<h4>Suggested Queries</h4>';

        // QA BUG FIX: guard against missing rule_name / process_name
        const seen = new Set();
        this.findings.slice(0, 8).forEach(f => {
            const ruleName    = f.rule_name    || 'Unknown Rule';
            const processName = f.process_name || 'Unknown Process';
            const key = `${processName}-${ruleName}`;
            if (seen.has(key)) return;
            seen.add(key);

            const item = document.createElement('div');
            item.className = 'suggestion-item';
            item.textContent = `Hunt: ${ruleName} — ${processName}`;
            item.addEventListener('click', () => {
                const sel = document.getElementById('filter-process_name');
                if (sel && processName !== 'Unknown Process') {
                    for (let opt of sel.options) {
                        if (opt.value.toLowerCase() === processName.toLowerCase()) {
                            sel.value = opt.value;
                            break;
                        }
                    }
                }
                this.generate();
            });
            container.appendChild(item);
        });

        // IP-based suggestions
        (this.facets.destination_ip || []).slice(0, 3).forEach(ip => {
            const item = document.createElement('div');
            item.className = 'suggestion-item';
            item.textContent = `Hunt connections to ${ip}`;
            item.addEventListener('click', () => {
                const sel = document.getElementById('filter-destination_ip');
                if (sel) sel.value = ip;
                this.generate();
            });
            container.appendChild(item);
        });
    },

    escapeHtml(s) {
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    },

    escapeAttr(s) {
        return s.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
};
