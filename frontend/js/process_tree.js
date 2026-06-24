/* ═══════════════════════════════════════════════════════════
   BlueHound — Hierarchical Process Tree View
   ═══════════════════════════════════════════════════════════ */

const ProcessTree = {
    _fullGraphData: null,

    // ── Severity normalization ────────────────────────────
    _normSev(s) {
        return (s || 'benign').toLowerCase();
    },

    // ── Filter support ───────────────────────────────────
    initFilters(graphData) {
        this._fullGraphData = graphData;
        const nodes = (graphData.nodes || []).filter(n => n.type === 'process' || n.type === undefined);

        const procs = [...new Set(nodes.map(n => n.process_name).filter(Boolean))].sort();
        const hosts = [...new Set(nodes.map(n => n.hostname).filter(Boolean))].sort();

        this._fillSelect('tf-proc', procs, 'All Processes');
        this._fillSelect('tf-host', hosts, 'All Hosts');

        ['tf-sev', 'tf-proc', 'tf-host'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('change', () => this.applyFilters());
        });
        const searchEl = document.getElementById('tf-search');
        if (searchEl) {
            let debounce;
            searchEl.addEventListener('input', () => {
                clearTimeout(debounce);
                debounce = setTimeout(() => this.applyFilters(), 300);
            });
        }
        const resetBtn = document.getElementById('tf-reset');
        if (resetBtn) resetBtn.addEventListener('click', () => this.resetFilters());
    },

    _fillSelect(id, values, defaultLabel) {
        const el = document.getElementById(id);
        if (!el) return;
        el.innerHTML = '';
        const def = document.createElement('option');
        def.value = ''; def.textContent = defaultLabel;
        el.appendChild(def);
        values.forEach(v => {
            const opt = document.createElement('option');
            opt.value = v; opt.textContent = v;
            el.appendChild(opt);
        });
    },

    applyFilters() {
        if (!this._fullGraphData) return;
        const sev    = (document.getElementById('tf-sev')?.value || '').toLowerCase();
        const proc   = document.getElementById('tf-proc')?.value || '';
        const host   = document.getElementById('tf-host')?.value || '';
        const search = (document.getElementById('tf-search')?.value || '').toLowerCase().trim();

        const noFilter = !sev && !proc && !host && !search;
        if (noFilter) {
            this.render(this._fullGraphData);
            return;
        }

        // Filter nodes, then rebuild graph with only matching subtrees
        const allNodes = this._fullGraphData.nodes || [];
        const allEdges = this._fullGraphData.edges || [];

        const matchedIds = new Set();
        allNodes.forEach(n => {
            const nSev = this._normSev(n.severity);
            if (sev && nSev !== sev) return;
            if (proc && n.process_name !== proc) return;
            if (host && n.hostname !== host) return;
            if (search) {
                const haystack = [n.process_name, n.commandline, n.hostname, n.user_name, n.label]
                    .filter(Boolean).join(' ').toLowerCase();
                if (!haystack.includes(search)) return;
            }
            matchedIds.add(n.id);
        });

        // Include ancestors (parents) so tree structure is preserved
        let added = true;
        while (added) {
            added = false;
            allEdges.forEach(e => {
                if (e.type === 'SPAWNED' && matchedIds.has(e.target) && !matchedIds.has(e.source)) {
                    matchedIds.add(e.source);
                    added = true;
                }
            });
        }
        // Include children of matched nodes
        allEdges.forEach(e => {
            if (e.type === 'SPAWNED' && matchedIds.has(e.source)) {
                matchedIds.add(e.target);
            }
        });

        const filteredNodes = allNodes.filter(n => matchedIds.has(n.id));
        const filteredEdges = allEdges.filter(e => matchedIds.has(e.source) && matchedIds.has(e.target));

        this.render({ nodes: filteredNodes, edges: filteredEdges });
    },

    resetFilters() {
        ['tf-sev', 'tf-proc', 'tf-host'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        const searchEl = document.getElementById('tf-search');
        if (searchEl) searchEl.value = '';
        if (this._fullGraphData) this.render(this._fullGraphData);
    },

    render(graphData) {
        const container = document.getElementById('tree-container');
        container.innerHTML = '';

        // Build tree from graph data
        const roots = this.buildTree(graphData);
        
        if (roots.length === 0) {
            container.innerHTML = '<p style="color:var(--text-muted);padding:40px;text-align:center;">No process tree data available.</p>';
            return;
        }

        roots.forEach(root => {
            container.appendChild(this.renderNode(root, true));
        });
    },

    buildTree(graphData) {
        const nodes = graphData.nodes || [];
        const edges = graphData.edges || [];
        
        // Only process nodes
        const processNodes = nodes.filter(n => n.type === 'process' || n.type === undefined);
        const nodeMap = {};
        processNodes.forEach(n => nodeMap[n.id] = { ...n, children: [] });

        const childIds = new Set();
        edges.forEach(e => {
            if (e.type === 'SPAWNED') {
                const parent = nodeMap[e.source];
                const child = nodeMap[e.target];
                if (parent && child) {
                    parent.children.push(child);
                    childIds.add(e.target);
                }
            }
        });

        // Roots = nodes that are not children
        const roots = Object.values(nodeMap).filter(n => !childIds.has(n.id));
        return roots.length > 0 ? roots : Object.values(nodeMap).slice(0, 1);
    },

    renderNode(node, isRoot = false) {
        const div = document.createElement('div');
        div.className = `tree-node ${isRoot ? 'tree-root' : ''}`;

        const sev = this._normSev(node.severity);
        const header = document.createElement('div');
        header.className = `tree-node-header sev-${sev}`;

        // Process name
        const nameSpan = document.createElement('span');
        nameSpan.className = 'tree-process-name';
        nameSpan.textContent = node.process_name || node.label || 'unknown';
        header.appendChild(nameSpan);

        // MITRE tags
        if (node.mitre) {
            node.mitre.filter(m => m).forEach(m => {
                const tag = document.createElement('span');
                tag.className = 'tree-mitre';
                tag.textContent = m;
                header.appendChild(tag);
            });
        }

        // Severity badge (use lowercase class for CSS consistency)
        if (sev !== 'benign') {
            const badge = document.createElement('span');
            badge.className = `finding-sev ${sev}`;
            badge.textContent = sev.toUpperCase();
            header.appendChild(badge);
        }

        // CommandLine
        if (node.commandline) {
            const cmdSpan = document.createElement('span');
            cmdSpan.className = 'tree-cmdline';
            cmdSpan.textContent = node.commandline;
            cmdSpan.title = node.commandline;
            cmdSpan.addEventListener('click', (e) => {
                e.stopPropagation();
                cmdSpan.classList.toggle('expanded');
            });
            header.appendChild(cmdSpan);
        }

        // Timestamp
        if (node.timestamp) {
            const ts = document.createElement('span');
            ts.className = 'tree-timestamp';
            ts.textContent = node.timestamp.replace('T', ' ').replace('Z', '');
            header.appendChild(ts);
        }

        // Click to show detail
        header.addEventListener('click', () => GraphView.showNodeDetail(node));

        div.appendChild(header);

        // Recurse children
        if (node.children && node.children.length > 0) {
            // Sort children by timestamp
            node.children.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
            node.children.forEach(child => {
                div.appendChild(this.renderNode(child));
            });
        }

        return div;
    }
};
