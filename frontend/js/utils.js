/* ═══════════════════════════════════════════════════════════
   BlueHound — Shared UI Utilities
   ═══════════════════════════════════════════════════════════
   Historically each panel defined its own `esc()` / `escapeHtml()` —
   five slightly different copies is exactly one HTML-escape bug waiting
   to happen. This module owns the canonical implementations. Old
   per-panel methods now delegate here.
*/

const BHUtils = (() => {
    // Textarea-based encoding: the browser's own HTML escape is safer than
    // hand-written replacements because it also handles rare edge cases.
    const _scratch = document.createElement('div');

    /** Escape untrusted text for safe interpolation into an HTML template. */
    function esc(value) {
        if (value === null || value === undefined) return '';
        _scratch.textContent = String(value);
        return _scratch.innerHTML;
    }

    /**
     * Escape and truncate — most panels also cap length for display.
     * Truncation happens *before* escaping so we don't split an entity.
     */
    function escTrunc(value, maxLen = 500) {
        if (value === null || value === undefined) return '';
        const s = String(value);
        return esc(s.length > maxLen ? s.slice(0, maxLen) + '…' : s);
    }

    return { esc, escTrunc };
})();

// Expose globally for panels that pre-date modules.
window.BHUtils = BHUtils;
