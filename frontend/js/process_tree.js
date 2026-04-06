/* ═══════════════════════════════════════════════════════════
   BlueHound — Hierarchical Process Tree View
   ═══════════════════════════════════════════════════════════ */

const ProcessTree = {
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

        const header = document.createElement('div');
        header.className = `tree-node-header sev-${node.severity || 'benign'}`;

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

        // Severity badge
        if (node.severity && node.severity !== 'benign') {
            const badge = document.createElement('span');
            badge.className = `finding-sev ${node.severity.toUpperCase()}`;
            badge.textContent = node.severity.toUpperCase();
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
