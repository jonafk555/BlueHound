/* ═══════════════════════════════════════════════════════════
   BlueHound — Event Timeline (D3.js Brush + Focus + Swim Lanes)
   ═══════════════════════════════════════════════════════════ */

const TimelineView = {
    events:   [],
    findings: [],
    enriched: [],
    brushSelection: null,   // current [t0, t1] brush range
    _observer: null,

    sevColors: {
        critical: '#ef4444',
        high:     '#f97316',
        medium:   '#eab308',
        low:      '#3b82f6',
        benign:   '#334155',
    },
    sevRank: { benign: 0, low: 1, medium: 2, high: 3, critical: 4 },

    // ── Public entry point ─────────────────────────────────
    init(events, findings) {
        this.events   = events   || [];
        this.findings = findings || [];
        this.enrichEvents();
        this.populateFilters();
        this.bindFilters();
        this.brushSelection = null;

        // Use ResizeObserver so we re-render whenever the panel becomes
        // visible and gets real dimensions (fixes the squashed layout bug).
        const mainEl = document.getElementById('timeline-main');
        if (this._observer) this._observer.disconnect();
        this._observer = new ResizeObserver(entries => {
            for (const e of entries) {
                if (e.contentRect.width > 50) this.render();
            }
        });
        this._observer.observe(mainEl);
    },

    // ── Enrich raw events with finding severity ────────────
    enrichEvents() {
        // Index findings by process_guid (per-event rules)
        const findByGuid = {};
        // Index findings by source_ip (correlation rules like TH-CORR-*)
        const findBySrcIp = {};
        this.findings.forEach(f => {
            const g = f.process_guid || '';
            if (g) {
                if (!findByGuid[g]) findByGuid[g] = [];
                findByGuid[g].push(f);
            }
            // Correlation findings (TH-CORR-*) match all events from same source_ip
            if (f.rule_id && f.rule_id.startsWith('TH-CORR') && f.source_ip) {
                if (!findBySrcIp[f.source_ip]) findBySrcIp[f.source_ip] = [];
                findBySrcIp[f.source_ip].push(f);
            }
        });

        this.enriched = this.events
            .filter(e => e.timestamp)
            .map(e => {
                const ts = new Date(e.timestamp);
                if (isNaN(ts)) return null;
                const guid  = e.process_guid || '';
                const srcIp = e.source_ip || '';
                // Merge rules from both guid-match and source_ip-match
                const rules = [
                    ...(findByGuid[guid] || []),
                    ...(findBySrcIp[srcIp] || []),
                ];
                let sev = 'benign';
                rules.forEach(r => {
                    const s = (r.severity || '').toLowerCase();
                    if ((this.sevRank[s] || 0) > (this.sevRank[sev] || 0)) sev = s;
                });
                return {
                    ts,
                    hostname:      e.hostname       || 'unknown',
                    process_name:  e.process_name   || '',
                    commandline:   e.commandline    || '',
                    user_name:     e.user_name      || '',
                    event_id:      e.event_id       || '',
                    source_ip:     e.source_ip      || '',
                    event_outcome: e.event_outcome  || '',
                    action_type:   e.action_type    || '',
                    // AD Object fields (EID 4662 / DCSync)
                    properties:    e.properties     || '',
                    object_guid:   e.object_guid    || '',
                    object_type:   e.object_type    || '',
                    access_mask:   e.access_mask    || '',
                    severity:      sev,
                    rules,
                };
            })
            .filter(Boolean)
            .sort((a, b) => a.ts - b.ts);
    },

    // ── Dropdowns ──────────────────────────────────────────
    populateFilters() {
        const hosts = [...new Set(this.enriched.map(e => e.hostname).filter(Boolean))].sort();
        const procs = [...new Set(this.enriched.map(e => e.process_name).filter(Boolean))].sort();

        const hostSel = document.getElementById('tl-filter-host');
        hostSel.innerHTML = '<option value="">All Hosts</option>';
        // VULN-09: use DOM API not innerHTML to safely insert untrusted values
        hosts.forEach(h => {
            const opt = document.createElement('option');
            opt.value = h;
            opt.textContent = h;
            hostSel.appendChild(opt);
        });

        const procSel = document.getElementById('tl-filter-proc');
        procSel.innerHTML = '<option value="">All Processes</option>';
        procs.forEach(p => {
            const opt = document.createElement('option');
            opt.value = p;
            opt.textContent = p;
            procSel.appendChild(opt);
        });
    },

    bindFilters() {
        ['tl-filter-host', 'tl-filter-sev', 'tl-filter-proc'].forEach(id => {
            document.getElementById(id).addEventListener('change', () => {
                this.brushSelection = null;
                this.render();
            });
        });
        document.getElementById('tl-reset-zoom').addEventListener('click', () => {
            this.brushSelection = null;
            document.getElementById('tl-time-label').textContent = 'Full Range';
            this.render();
        });
    },

    // ── Filter data ────────────────────────────────────────
    getFiltered() {
        const host = document.getElementById('tl-filter-host').value;
        const sev  = document.getElementById('tl-filter-sev').value;
        const proc = document.getElementById('tl-filter-proc').value;

        return this.enriched.filter(e => {
            if (host && e.hostname !== host)       return false;
            if (proc && e.process_name !== proc)   return false;
            if (sev) {
                if (sev === 'malicious') return e.severity !== 'benign';
                if (e.severity !== sev)  return false;
            }
            return true;
        });
    },

    // ── Main render ────────────────────────────────────────
    render() {
        const data = this.getFiltered();
        if (!data.length) return;

        const mainContainer = document.getElementById('timeline-main');
        const ctxContainer  = document.getElementById('timeline-context');

        const W = mainContainer.clientWidth;
        const H = mainContainer.clientHeight;
        if (W < 50 || H < 50) return;   // panel still hidden

        const M  = { top: 24, right: 20, bottom: 36, left: 160 };
        const CM = { top:  6, right: 20, bottom: 22, left: 160 };
        const CTX_H = 56;

        const innerW  = W - M.left  - M.right;
        const innerH  = H - M.top   - M.bottom;

        // ── Swim lanes (Y axis = host) ──────────────────────
        const hosts = [...new Set(data.map(e => e.hostname))].sort();
        const yScale = d3.scaleBand()
            .domain(hosts)
            .range([0, innerH])
            .padding(0.35);

        // ── Time scales ─────────────────────────────────────
        const fullExtent = d3.extent(data, d => d.ts);
        const pad        = Math.max((fullExtent[1] - fullExtent[0]) * 0.02, 30000);
        const fullDomain = [new Date(+fullExtent[0] - pad), new Date(+fullExtent[1] + pad)];

        // Focus domain: use brush selection if active, else full
        let focusDomain = this.brushSelection
            ? [this.brushSelection[0], this.brushSelection[1]]
            : fullDomain;

        const xFocus = d3.scaleTime().domain(focusDomain).range([0, innerW]);
        const xCtx   = d3.scaleTime().domain(fullDomain).range([0, innerW]);

        // ── Draw main SVG ───────────────────────────────────
        const mainSvgEl = document.getElementById('timeline-svg');
        mainSvgEl.innerHTML = '';
        const svgW = W;
        const svgH = H;
        mainSvgEl.setAttribute('width',  svgW);
        mainSvgEl.setAttribute('height', svgH);

        const svg = d3.select(mainSvgEl);

        // Clip path
        svg.append('defs').append('clipPath').attr('id', 'tl-clip')
            .append('rect').attr('width', innerW).attr('height', innerH + 10);

        const g = svg.append('g').attr('transform', `translate(${M.left},${M.top})`);

        // Grid lines (vertical)
        g.append('g').attr('class', 'tl-grid')
            .attr('transform', `translate(0,${innerH})`)
            .call(
                d3.axisBottom(xFocus).ticks(8)
                    .tickSize(-innerH)
                    .tickFormat('')
            )
            .selectAll('line').attr('stroke', '#1e293b').attr('stroke-dasharray', '3,3');
        g.select('.tl-grid .domain').remove();

        // Host lane backgrounds
        hosts.forEach((h, i) => {
            g.append('rect')
                .attr('x', 0).attr('y', yScale(h))
                .attr('width', innerW).attr('height', yScale.bandwidth())
                .attr('fill', i % 2 === 0 ? 'rgba(255,255,255,0.018)' : 'rgba(255,255,255,0.036)')
                .attr('rx', 3);
        });

        // X axis (focus)
        const xAxisG = g.append('g').attr('class', 'tl-axis')
            .attr('transform', `translate(0,${innerH})`)
            .call(d3.axisBottom(xFocus).ticks(8).tickFormat(d3.timeFormat('%H:%M:%S')));
        xAxisG.select('.domain').attr('stroke', '#334155');

        // Y axis (hosts)
        const yAxisG = g.append('g').attr('class', 'tl-axis')
            .call(d3.axisLeft(yScale).tickSize(0));
        yAxisG.select('.domain').remove();
        yAxisG.selectAll('text')
            .attr('fill', '#94a3b8')
            .attr('font-size', '11px')
            .attr('dx', '-6');

        // ── Event dots ──────────────────────────────────────
        const dotsG = g.append('g').attr('clip-path', 'url(#tl-clip)');

        // Pulse halos for critical/high (drawn first, behind dots)
        dotsG.selectAll('.tl-halo')
            .data(data.filter(d => d.severity === 'critical' || d.severity === 'high'))
            .join('circle')
            .attr('class', 'tl-halo')
            .attr('cx', d => xFocus(d.ts))
            .attr('cy', d => yScale(d.hostname) + yScale.bandwidth() / 2)
            .attr('r',  d => d.severity === 'critical' ? 13 : 11)
            .attr('fill', 'none')
            .attr('stroke', d => this.sevColors[d.severity])
            .attr('stroke-width', 1.5)
            .attr('opacity', 0.25)
            .style('pointer-events', 'none');

        const dot = dotsG.selectAll('.tl-dot')
            .data(data)
            .join('circle')
            .attr('class', d => `tl-dot tl-sev-${d.severity}`)
            .attr('cx', d => xFocus(d.ts))
            .attr('cy', d => yScale(d.hostname) + yScale.bandwidth() / 2)
            .attr('r',  d => ({ critical: 8, high: 7, medium: 6, low: 5, benign: 3.5 }[d.severity] || 4))
            .attr('fill',   d => this.sevColors[d.severity] || this.sevColors.benign)
            .attr('stroke', d => d.severity !== 'benign' ? this.sevColors[d.severity] : 'transparent')
            .attr('stroke-width', 2)
            .attr('stroke-opacity', 0.5)
            .attr('opacity', d => d.severity === 'benign' ? 0.45 : 0.92)
            .style('cursor', 'pointer')
            .on('mouseover', (ev, d) => this.showTooltip(ev, d))
            .on('mousemove', (ev)    => this.moveTooltip(ev))
            .on('mouseout',  ()      => this.hideTooltip())
            .on('click',     (ev, d) => this.showDetail(d));

        // Severity mini legend (top-right)
        const lgItems = ['critical','high','medium','low','benign'];
        const lgG = g.append('g').attr('transform', `translate(${innerW - lgItems.length * 68},${-18})`);
        lgItems.forEach((s, i) => {
            lgG.append('circle').attr('cx', i * 68).attr('cy', 7).attr('r', 5)
                .attr('fill', this.sevColors[s]);
            lgG.append('text').attr('x', i * 68 + 8).attr('y', 11)
                .attr('fill', '#64748b').attr('font-size', '10px').text(s);
        });

        // Store for brush updates
        this._dotsG   = dotsG;
        this._xFocus  = xFocus;
        this._xCtx    = xCtx;
        this._xAxisG  = xAxisG;
        this._yScale  = yScale;
        this._data    = data;

        // ── Context (brush) SVG ─────────────────────────────
        const ctxSvgEl = document.getElementById('timeline-brush-svg');
        ctxSvgEl.innerHTML = '';
        ctxSvgEl.setAttribute('width',  W);
        ctxSvgEl.setAttribute('height', CTX_H + CM.top + CM.bottom);

        this._ctxSvg = d3.select(ctxSvgEl);
        const ctxG = this._ctxSvg.append('g')
            .attr('transform', `translate(${CM.left},${CM.top})`);

        // Mini x axis
        ctxG.append('g').attr('class', 'tl-axis')
            .attr('transform', `translate(0,${CTX_H})`)
            .call(d3.axisBottom(xCtx).ticks(10).tickFormat(d3.timeFormat('%H:%M')))
            .select('.domain').attr('stroke', '#334155');

        // Mini bars (stacked by host, colored by severity)
        ctxG.selectAll('.tl-ctx-bar')
            .data(data)
            .join('rect')
            .attr('x',      d => xCtx(d.ts) - 1)
            .attr('y',      d => d.severity !== 'benign' ? 0 : CTX_H * 0.55)
            .attr('width',  2)
            .attr('height', d => d.severity !== 'benign' ? CTX_H : CTX_H * 0.35)
            .attr('fill',   d => this.sevColors[d.severity] || this.sevColors.benign)
            .attr('opacity', d => d.severity !== 'benign' ? 0.85 : 0.22);

        // Brush
        this._brush = d3.brushX()
            .extent([[0, 0], [innerW, CTX_H]])
            .on('brush end', ev => this._onBrush(ev, fullDomain));

        const brushG = ctxG.append('g').attr('class', 'brush').call(this._brush);

        // Restore previous brush selection visually
        if (this.brushSelection) {
            const [t0, t1] = this.brushSelection;
            brushG.call(this._brush.move, [xCtx(t0), xCtx(t1)]);
        }
    },

    // ── Brush handler ──────────────────────────────────────
    _onBrush(event, fullDomain) {
        if (!event.selection) {
            this.brushSelection = null;
            document.getElementById('tl-time-label').textContent = 'Full Range';
        } else {
            const [x0, x1] = event.selection;
            const t0 = this._xCtx.invert(x0);
            const t1 = this._xCtx.invert(x1);
            this.brushSelection = [t0, t1];

            const fmt = d3.timeFormat('%H:%M:%S');
            document.getElementById('tl-time-label').textContent = `${fmt(t0)} — ${fmt(t1)}`;

            // Update focus scale & redraw dots + axis
            this._xFocus.domain([t0, t1]);

            this._dotsG.selectAll('.tl-dot')
                .attr('cx', d => this._xFocus(d.ts));
            this._dotsG.selectAll('.tl-halo')
                .attr('cx', d => this._xFocus(d.ts));
            this._xAxisG.call(
                d3.axisBottom(this._xFocus).ticks(8)
                    .tickFormat(d3.timeFormat('%H:%M:%S'))
            );
            this._xAxisG.select('.domain').attr('stroke', '#334155');
        }
    },

    // ── Tooltip ────────────────────────────────────────────
    showTooltip(ev, d) {
        const tip = document.getElementById('tl-tooltip');
        const isBad = d.severity !== 'benign';
        const sevBadge = isBad
            ? `<span class="tl-tip-sev tl-tip-${d.severity}">${d.severity.toUpperCase()}</span>` : '';
        const rulesHtml = d.rules.length
            ? `<div class="tl-tip-rules">${d.rules.map(r => `<div>⚠ ${this.esc(r.rule_name)}</div>`).join('')}</div>` : '';

        // EID 4662: show AD fields, not CommandLine
        const isADEvent = String(d.event_id) === '4662';
        let bodyHtml;
        if (isADEvent && d.properties) {
            bodyHtml = `<div class="tl-tip-cmd" style="color:#f97316;">`
                + `AD Replication Right:<br>${this.esc(d.properties)}</div>`;
        } else {
            const shortCmd = (d.commandline || '').substring(0, 130);
            bodyHtml = d.commandline
                ? `<div class="tl-tip-cmd">${this.esc(shortCmd)}${d.commandline.length > 130 ? '…' : ''}</div>`
                : '';
        }

        const displayName = d.process_name || (isADEvent ? 'AD Object Access' : 'unknown');
        tip.innerHTML = `
            <div class="tl-tip-header">${sevBadge}<strong>${this.esc(displayName)}</strong></div>
            <div class="tl-tip-time">${d.ts.toISOString().replace('T',' ').replace('Z','')}</div>
            <div class="tl-tip-host">${this.esc(d.hostname)} · ${this.esc(d.user_name)}</div>
            ${bodyHtml}
            ${rulesHtml}`;
        tip.classList.remove('hidden');
        this.moveTooltip(ev);
    },
    moveTooltip(ev) {
        const tip = document.getElementById('tl-tooltip');
        const x = ev.pageX + 16, y = ev.pageY - 8;
        const overflowX = x + 420 > window.innerWidth;
        tip.style.left  = (overflowX ? ev.pageX - 430 : x) + 'px';
        tip.style.top   = Math.max(0, y) + 'px';
    },
    hideTooltip() {
        document.getElementById('tl-tooltip').classList.add('hidden');
    },

    // -- Click detail card
    showDetail(d) {
        const panel   = document.getElementById("timeline-detail");
        const content = document.getElementById("timeline-detail-content");
        const sevCls  = `badge-${d.severity}`;
        const isADEvent = String(d.event_id) === "4662";
        const displayName = d.process_name || (isADEvent ? "AD Object Access (DCSync)" : "unknown");

        const rulesHtml = d.rules.map(r => {
            const ruleSev = (r.severity || '').toLowerCase();
            return `<div class="detail-rule">
                <div class="detail-rule-name">${this.esc(r.rule_name)}</div>
                <span class="finding-sev ${ruleSev}">${ruleSev.toUpperCase()}</span>
            </div>`;
        }).join("");

        let activityHtml = "", llmBtnHtml = "", llmCtx = null;

        if (isADEvent) {
            const guidNames = {
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
                "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
            };
            const guidLabel = guidNames[d.object_guid] || d.object_guid || "—";
            const propLabel = d.properties || "—";
            const isDCSync  = propLabel.includes("Replication") || Object.keys(guidNames).includes(d.object_guid);

            activityHtml = `
                <div class="detail-field">
                    <div class="detail-field-label" style="color:#f97316;">AD Object Access Details (EID 4662)</div>
                </div>
                <div class="detail-field">
                    <div class="detail-field-label">Replication Right (Properties)</div>
                    <div class="detail-field-value mono" style="color:#f97316;">${this.esc(propLabel)}</div>
                </div>
                <div class="detail-field">
                    <div class="detail-field-label">Object GUID</div>
                    <div class="detail-field-value mono">${this.esc(guidLabel)}</div>
                </div>
                ${d.object_type ? `<div class="detail-field">
                    <div class="detail-field-label">Object Type</div>
                    <div class="detail-field-value">${this.esc(d.object_type)}</div>
                </div>` : ""}
                ${d.access_mask ? `<div class="detail-field">
                    <div class="detail-field-label">Access Mask</div>
                    <div class="detail-field-value mono">${this.esc(d.access_mask)}</div>
                </div>` : ""}
                ${isDCSync ? `<div style="margin-top:8px;padding:8px;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.3);border-radius:6px;font-size:11px;color:#ef4444;">⚠ DCSync: Non-DC account exercised AD replication rights. Initiating PowerShell (lsadump::dcsync) is on WIN-WS02 at ~09:30:00.</div>` : ""}`;

            llmBtnHtml = `<button class="btn-primary" id="tl-detail-llm-btn" style="margin-top:10px;font-size:12px;padding:5px 14px;">Analyze in LLM</button>`;
            llmCtx = { commandline: d.properties || d.object_guid, event_id: d.event_id,
                process_name: "AD Object Access", hostname: d.hostname, user_name: d.user_name,
                matched_rules: d.rules.map(r => ({ name: r.rule_name, severity: r.severity })),
                properties: d.properties };
        } else {
            const ips  = (d.commandline.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b/g) || []);
            const urls = (d.commandline.match(/https?:\/\/[^\s'"\)\]]+/g) || []);
            const iocs = [...new Set([...ips, ...urls])];
            const iocHtml = iocs.length
                ? `<div class="detail-field"><div class="detail-field-label">Embedded IPs / URLs</div>` +
                  iocs.map(l => {
                      const ext = !l.match(/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/);
                      return `<div class="detail-field-value mono" style="color:${ext ? "#ef4444" : "#22c55e"};margin-bottom:4px;">${ext ? "⚠" : "●"} ${this.esc(l)}</div>`;
                  }).join("") + "</div>"
                : "";
            activityHtml = `
                ${d.commandline ? `<div class="detail-field">
                    <div class="detail-field-label">CommandLine</div>
                    <div class="detail-field-value mono">${this.esc(d.commandline)}</div>
                </div>` : ""}
                ${iocHtml}`;
            if (d.commandline) {
                llmBtnHtml = `<button class="btn-primary" id="tl-detail-llm-btn" style="margin-top:10px;font-size:12px;padding:5px 14px;">Analyze in LLM</button>`;
                llmCtx = { commandline: d.commandline, event_id: d.event_id,
                    process_name: d.process_name, hostname: d.hostname, user_name: d.user_name,
                    matched_rules: d.rules.map(r => ({ name: r.rule_name, severity: r.severity })),
                    properties: null };
            }
        }

        content.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                <div style="display:flex;align-items:center;gap:8px;">
                    <span class="detail-sev-badge ${sevCls}">${d.severity}</span>
                    <strong style="font-size:14px;">${this.esc(displayName)}</strong>
                </div>
                <button id="tl-detail-close-btn"
                    style="background:none;border:none;color:#94a3b8;cursor:pointer;font-size:18px;line-height:1;">✕</button>
            </div>
            <div class="detail-field">
                <div class="detail-field-label">Timestamp</div>
                <div class="detail-field-value mono">${d.ts.toISOString()}</div>
            </div>
            <div class="detail-field">
                <div class="detail-field-label">Host / User</div>
                <div class="detail-field-value">${this.esc(d.hostname)} · ${this.esc(d.user_name)}</div>
            </div>
            <div class="detail-field">
                <div class="detail-field-label">Event ID</div>
                <div class="detail-field-value">${this.esc(d.event_id)}</div>
            </div>
            ${activityHtml}
            ${rulesHtml ? `<div class="detail-field"><div class="detail-field-label">Matched Rules</div>${rulesHtml}</div>` : ""}
            ${llmBtnHtml}
        `;

        // Close button listener (CSP blocks inline onclick)
        const closeBtn = document.getElementById("tl-detail-close-btn");
        if (closeBtn) {
            closeBtn.addEventListener("click", () => {
                panel.classList.add("hidden");
            });
        }

        const llmBtn = document.getElementById("tl-detail-llm-btn");
        if (llmBtn && llmCtx) {
            llmBtn.addEventListener("click", () => {
                LLMPanel.analyzeFromGraph(llmCtx);
                BlueHound.switchPanel("llm");
            });
        }
        panel.classList.remove("hidden");
    },
    esc(s) {
        const div = document.createElement('div');
        div.textContent = String(s);
        return div.innerHTML;
    },
};
