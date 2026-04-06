/* ═══════════════════════════════════════════════════════════
   BlueHound — D3.js Force-Directed Graph (BloodHound Style)
   ═══════════════════════════════════════════════════════════ */

// VULN-16: Validate MITRE ID before using in window.open() URL
const _MITRE_ID_RE = /^T\d{4}(\.\d{3})?$/;
function _safeMitreUrl(id) {
    if (!_MITRE_ID_RE.test(String(id))) return null;
    return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';
}

const GraphView = {
    svg: null,
    g: null,
    simulation: null,
    zoom: null,
    graphData: null,

    severityColors: {
        critical: '#ef4444',
        high:     '#f97316',
        medium:   '#eab308',
        low:      '#3b82f6',
        benign:   '#22c55e',
    },

    typeColors: {
        network: '#a78bfa',
    },

    render(graphData) {
        this.graphData = graphData;
        const container = document.getElementById('graph-container');
        const svgEl = document.getElementById('graph-svg');
        
        // Clear previous
        svgEl.innerHTML = '';
        
        const width = container.clientWidth;
        const height = container.clientHeight;

        this.svg = d3.select(svgEl)
            .attr('width', width)
            .attr('height', height);

        // Defs for glow filters and arrows
        const defs = this.svg.append('defs');
        
        // Glow filter
        const glow = defs.append('filter').attr('id', 'glow');
        glow.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'coloredBlur');
        const merge = glow.append('feMerge');
        merge.append('feMergeNode').attr('in', 'coloredBlur');
        merge.append('feMergeNode').attr('in', 'SourceGraphic');

        // Arrow marker
        defs.append('marker')
            .attr('id', 'arrow')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 20)
            .attr('refY', 0)
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('fill', '#334155');

        // Zoom setup
        this.zoom = d3.zoom()
            .scaleExtent([0.1, 5])
            .on('zoom', (event) => {
                this.g.attr('transform', event.transform);
            });
        this.svg.call(this.zoom);

        this.g = this.svg.append('g');

        const nodes = graphData.nodes || [];
        const edges = graphData.edges || [];

        // Build links (D3 needs source/target as node objects)
        const nodeMap = {};
        nodes.forEach(n => nodeMap[n.id] = n);
        const links = edges.filter(e => nodeMap[e.source] && nodeMap[e.target])
            .map(e => ({ ...e, source: e.source, target: e.target }));

        // Simulation
        this.simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(120))
            .force('charge', d3.forceManyBody().strength(-400))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(30));

        // Edges
        const link = this.g.append('g').selectAll('line')
            .data(links)
            .join('line')
            .attr('class', 'graph-edge')
            .attr('marker-end', 'url(#arrow)');

        // Edge labels
        const edgeLabel = this.g.append('g').selectAll('text')
            .data(links)
            .join('text')
            .attr('class', 'graph-edge-label')
            .text(d => d.label);

        // Nodes
        const node = this.g.append('g').selectAll('g')
            .data(nodes)
            .join('g')
            .attr('class', 'graph-node')
            .call(d3.drag()
                .on('start', (e, d) => this.dragStart(e, d))
                .on('drag', (e, d) => this.dragging(e, d))
                .on('end', (e, d) => this.dragEnd(e, d))
            )
            .on('click', (e, d) => this.showNodeDetail(d));

        // Node circles
        node.append('circle')
            .attr('r', d => d.type === 'network' ? 8 : (d.severity === 'critical' ? 14 : d.severity === 'high' ? 12 : 10))
            .attr('fill', d => this.getNodeColor(d))
            .attr('stroke', d => this.getNodeColor(d))
            .attr('stroke-width', d => d.severity === 'critical' || d.severity === 'high' ? 2 : 1)
            .attr('stroke-opacity', 0.5)
            .attr('filter', d => (d.severity === 'critical' || d.severity === 'high') ? 'url(#glow)' : null);

        // Node labels
        node.append('text')
            .attr('class', 'graph-label')
            .attr('dy', d => (d.type === 'network' ? 18 : (d.severity === 'critical' ? 26 : 22)))
            .text(d => d.label || d.process_name || d.id.substring(0, 8));

        // Tick update
        this.simulation.on('tick', () => {
            link.attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            edgeLabel.attr('x', d => (d.source.x + d.target.x) / 2)
                     .attr('y', d => (d.source.y + d.target.y) / 2);

            node.attr('transform', d => `translate(${d.x},${d.y})`);
        });

        // Controls
        document.getElementById('graph-zoom-in').onclick = () => this.svg.transition().call(this.zoom.scaleBy, 1.3);
        document.getElementById('graph-zoom-out').onclick = () => this.svg.transition().call(this.zoom.scaleBy, 0.7);
        document.getElementById('graph-reset').onclick = () => this.svg.transition().call(this.zoom.transform, d3.zoomIdentity);
    },

    getNodeColor(node) {
        if (node.type === 'network') return this.typeColors.network;
        return this.severityColors[node.severity] || this.severityColors.benign;
    },

    dragStart(event, d) {
        if (!event.active) this.simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    },

    dragging(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    },

    dragEnd(event, d) {
        if (!event.active) this.simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    },

    showNodeDetail(node) {
        const sidebar = document.getElementById('node-detail');
        const content = document.getElementById('detail-content');
        
        const sevClass = `badge-${node.severity || 'benign'}`;
        let rulesHtml = '';
        if (node.rules && node.rules.length > 0) {
            rulesHtml = '<div class="detail-field"><div class="detail-field-label">Matched Rules</div>';
            node.rules.forEach(r => {
                // VULN-18: escape r.name and r.severity — both come from log data (attacker-controlled)
                const safeName = this.escapeHtml(String(r.name || ''));
                const safeSev  = this.escapeHtml(String(r.severity || ''));
                rulesHtml += `<div class="detail-rule">
                    <div class="detail-rule-name">${safeName}</div>
                    <span class="finding-sev ${safeSev}">${safeSev}</span>
                </div>`;
            });
            rulesHtml += '</div>';
        }

        let mitreHtml = '';
        const _validMitre = (node.mitre || []).filter(m => m && _MITRE_ID_RE.test(String(m)));
        if (_validMitre.length > 0) {
            mitreHtml = '<div class="detail-field"><div class="detail-field-label">MITRE ATT&CK</div><div>';
            // VULN-16: use data-mid placeholder; bind click with addEventListener after innerHTML is set
            _validMitre.forEach(m => {
                mitreHtml += `<span class="detail-mitre-tag _mitre-placeholder" data-mid="${this.escapeHtml(m)}"></span>`;
            });
            mitreHtml += '</div></div>';
        }

        // Show connected IPs for process nodes
        let connectedIps = '';
        if (node.type !== 'network' && this.graphData) {
            const ips = (this.graphData.edges || [])
                .filter(e => {
                    const srcId = typeof e.source === 'object' ? e.source.id : e.source;
                    return srcId === node.id && e.type === 'CONNECTED';
                })
                .map(e => {
                    const targetId = typeof e.target === 'object' ? e.target.id : e.target;
                    const targetNode = (this.graphData.nodes || []).find(n => n.id === targetId);
                    return targetNode ? targetNode.label : targetId;
                });
            if (ips.length > 0) {
                connectedIps = '<div class="detail-field"><div class="detail-field-label">Connected IPs (Sysmon EID 3)</div>';
                ips.forEach(ip => {
                    connectedIps += `<div class="detail-field-value mono" style="color:#a78bfa;margin-bottom:4px;">⬤ ${this.escapeHtml(ip)}</div>`;
                });
                connectedIps += '</div>';
            }
        }

        // Extract IPs/URLs embedded in CommandLine
        let cmdlineLinks = '';
        if (node.commandline) {
            const ipMatches = node.commandline.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b/g) || [];
            const urlMatches = node.commandline.match(/https?:\/\/[^\s'")\]]+/g) || [];
            const allLinks = [...new Set([...ipMatches, ...urlMatches])];
            if (allLinks.length > 0) {
                cmdlineLinks = '<div class="detail-field"><div class="detail-field-label">Embedded IPs / URLs</div>';
                allLinks.forEach(link => {
                    const isExternal = !link.match(/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/);
                    cmdlineLinks += `<div class="detail-field-value mono" style="color:${isExternal ? '#ef4444' : '#22c55e'};margin-bottom:4px;">${isExternal ? '⚠' : '●'} ${this.escapeHtml(link)}</div>`;
                });
                cmdlineLinks += '</div>';
            }
        }

        content.innerHTML = `
            <div class="detail-header">
                <span class="detail-sev-badge ${sevClass}">${node.severity || 'benign'}</span>
                <span style="font-size:16px;font-weight:600;">${node.label || node.process_name || 'Unknown'}</span>
            </div>
            ${this.detailField('Process Name', node.process_name)}
            ${this.detailField('Process Path', node.process_path, true)}
            ${this.detailField('CommandLine', node.commandline, true)}
            ${this.detailField('Hostname', node.hostname)}
            ${this.detailField('User', node.user_name)}
            ${this.detailField('Timestamp', node.timestamp)}
            ${this.detailField('Event ID', node.event_id)}
            ${this.detailField('Hashes', node.hashes, true)}
            ${node.type === 'network' ? this.detailField('Destination', `${node.destination_ip}:${node.destination_port}`) : ''}
            ${connectedIps}
            ${cmdlineLinks}
            ${mitreHtml}
            ${rulesHtml}
            ${node.commandline ? '<button class="btn-primary" id="detail-llm-btn" style="margin-top:12px;font-size:12px;padding:6px 14px;">Analyze in LLM</button>' : ''}
        `;

        // VULN-16: Re-bind MITRE tags with safe addEventListener after innerHTML is set
        content.querySelectorAll('._mitre-placeholder[data-mid]').forEach(el => {
            const mid = el.getAttribute('data-mid');
            const url = _safeMitreUrl(mid);
            el.textContent = mid;
            el.classList.remove('_mitre-placeholder');
            if (url) {
                el.addEventListener('click', () => window.open(url, '_blank', 'noopener,noreferrer'));
            }
        });

        const llmBtn = document.getElementById('detail-llm-btn');
        if (llmBtn && node.commandline) {
            llmBtn.addEventListener('click', () => {
                LLMPanel.analyzeFromGraph(node.commandline);
            });
        }

        sidebar.classList.remove('hidden');
        document.getElementById('detail-close').onclick = () => sidebar.classList.add('hidden');
    },

    detailField(label, value, mono = false) {
        if (!value) return '';
        return `<div class="detail-field">
            <div class="detail-field-label">${label}</div>
            <div class="detail-field-value ${mono ? 'mono' : ''}">${this.escapeHtml(String(value))}</div>
        </div>`;
    },

    escapeHtml(s) {
        const div = document.createElement('div');
        div.textContent = s;
        return div.innerHTML;
    },

    resize() {
        if (!this.graphData) return;
        const container = document.getElementById('graph-container');
        this.svg.attr('width', container.clientWidth).attr('height', container.clientHeight);
        if (this.simulation) {
            this.simulation.force('center', d3.forceCenter(container.clientWidth / 2, container.clientHeight / 2));
            this.simulation.alpha(0.3).restart();
        }
    }
};
