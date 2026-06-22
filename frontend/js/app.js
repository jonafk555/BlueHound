/* ═══════════════════════════════════════════════════════════
   BlueHound — App State & Router
   ═══════════════════════════════════════════════════════════ */

const BlueHound = {
    state: {
        events: [],
        findings: [],
        graph: null,
        facets: {},
        llmPrescan: null,
        activePanel: 'landing',
        selectedFormat: 'kql',
    },

    init() {
        this.bindNav();
        this.bindUpload();
        this.bindDemo();
    },

    bindNav() {
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                if (!this.state.graph) {
                    // QA UX FIX: Instead of silently ignoring, show a toast hint
                    this._showToast('Please load a dataset first using the “Load Demo” button.');
                    return;
                }
                this.switchPanel(tab.dataset.panel);
            });
        });
    },

    bindUpload() {
        const fileInput = document.getElementById('file-input');
        fileInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            await this.uploadFile(file);
        });
    },

    bindDemo() {
        // Dropdown toggles
        this._bindDropdown('load-sample-btn', 'sample-menu');
        this._bindDropdown('landing-demo-btn', 'landing-sample-menu');
        // Bind all sample-option buttons
        document.querySelectorAll('.sample-option').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const ds = e.target.getAttribute('data-dataset');
                // Close all dropdowns
                document.querySelectorAll('.sample-menu').forEach(m => m.classList.remove('open'));
                this.loadSample(ds || 'enterprise');
            });
        });
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.sample-dropdown')) {
                document.querySelectorAll('.sample-menu').forEach(m => m.classList.remove('open'));
            }
        });
    },

    _bindDropdown(btnId, menuId) {
        const btn = document.getElementById(btnId);
        const menu = document.getElementById(menuId);
        if (btn && menu) {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                // Close other menus first
                document.querySelectorAll('.sample-menu').forEach(m => {
                    if (m !== menu) m.classList.remove('open');
                });
                menu.classList.toggle('open');
            });
        }
    },

    async uploadFile(file) {
        const MAX_SIZE_MB = 200;
        const MAX_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024;
        if (file.size > MAX_SIZE_BYTES) {
            this._showToast(`File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Maximum is ${MAX_SIZE_MB} MB.`, 'error');
            return;
        }
        const sizeMB = (file.size / 1024 / 1024).toFixed(1);
        const isLarge = file.size > 50 * 1024 * 1024;
        this.showLoading(isLarge
            ? `Uploading ${sizeMB} MB — this may take a moment...`
            : 'Ingesting & analyzing logs...');
        try {
            const form = new FormData();
            form.append('file', file);
            const resp = await fetch('/api/upload', { method: 'POST', body: form });
            if (!resp.ok) {
                let msg = `Server error (${resp.status})`;
                try { const e = await resp.json(); msg = e.error || msg; } catch (_) {}
                throw new Error(msg);
            }
            const data = await resp.json();
            this.onDataLoaded(data);
        } catch (err) {
            this._showToast('Upload failed: ' + err.message, 'error');
        } finally {
            this.hideLoading();
        }
    },

    async loadSample(dataset = 'enterprise') {
        this.showLoading('Loading demo dataset...');
        try {
            const resp = await fetch(`/api/sample?dataset=${encodeURIComponent(dataset)}`);
            if (!resp.ok) {
                let msg = `Server error (${resp.status})`;
                try { const e = await resp.json(); msg = e.error || msg; } catch (_) {}
                throw new Error(msg);
            }
            const data = await resp.json();
            this.onDataLoaded(data);
        } catch (err) {
            this._showToast('Demo load failed: ' + err.message, 'error');
        } finally {
            this.hideLoading();
        }
    },

    onDataLoaded(data) {
        this.state.events = data.events || [];
        this.state.findings = data.findings || [];
        this.state.graph = data.graph || { nodes: [], edges: [] };
        this.state.facets = data.facets || {};
        this.state.llmPrescan = data.llm_prescan || null;

        // Update stats
        this.updateStats(data);
        document.getElementById('stats-bar').classList.remove('hidden');
        document.getElementById('main-content').classList.add('has-stats');

        // Init all panels
        GraphView.render(this.state.graph);
        ProcessTree.render(this.state.graph);
        HuntPanel.render(this.state.findings);
        QueryPanel.init(this.state.facets, this.state.findings);
        LLMPanel.init(this.state.events, this.state.findings, this.state.llmPrescan);
        TimelineView.init(this.state.events, this.state.findings);

        // Switch to graph
        this.switchPanel('graph');
    },

    updateStats(data) {
        document.getElementById('stat-events').textContent = data.event_count || 0;
        document.getElementById('stat-findings').textContent = data.finding_count || 0;
        const stats = data.graph?.stats || {};
        document.getElementById('stat-nodes').textContent = stats.total_nodes || 0;
        document.getElementById('stat-edges').textContent = stats.total_edges || 0;
        document.getElementById('stat-critical').textContent = stats.critical || 0;
        document.getElementById('stat-high').textContent = stats.high || 0;
        document.getElementById('stat-medium').textContent = stats.medium || 0;
    },

    switchPanel(name) {
        this.state.activePanel = name;
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        const panel = document.getElementById(`panel-${name}`);
        const tab = document.querySelector(`.nav-tab[data-panel="${name}"]`);
        if (panel) panel.classList.add('active');
        if (tab) tab.classList.add('active');

        // Re-render graph when switching to it (SVG sizing)
        if (name === 'graph' && this.state.graph) {
            setTimeout(() => GraphView.resize(), 50);
        }
        // Re-render timeline when switching to it
        if (name === 'timeline' && this.state.events.length > 0) {
            setTimeout(() => TimelineView.render(), 50);
        }
    },

    showLoading(msg) {
        const overlay = document.getElementById('loading-overlay');
        overlay.querySelector('.loading-text').textContent = msg || 'Processing...';
        overlay.classList.remove('hidden');
    },

    hideLoading() {
        document.getElementById('loading-overlay').classList.add('hidden');
    },

    // QA FIX: Non-blocking toast instead of alert()
    _showToast(message, type = 'info') {
        let toast = document.getElementById('bh-toast');
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'bh-toast';
            toast.style.cssText = [
                'position:fixed', 'bottom:24px', 'left:50%', 'transform:translateX(-50%)',
                'background:var(--surface-2,#1e293b)', 'color:var(--text-primary,#f1f5f9)',
                'padding:10px 20px', 'border-radius:8px', 'font-size:13px',
                'z-index:9999', 'box-shadow:0 4px 24px rgba(0,0,0,.4)',
                'border:1px solid var(--border,#334155)', 'max-width:480px',
                'text-align:center', 'pointer-events:none',
            ].join(';');
            document.body.appendChild(toast);
        }
        // XSS-safe: set text content, not innerHTML
        toast.textContent = message;
        toast.style.borderColor = type === 'error' ? '#ef4444' : 'var(--border,#334155)';
        toast.style.opacity = '1';
        toast.style.transition = 'opacity 0.3s';
        clearTimeout(toast._timer);
        toast._timer = setTimeout(() => {
            toast.style.opacity = '0';
        }, 4000);
    }
};

document.addEventListener('DOMContentLoaded', () => BlueHound.init());
