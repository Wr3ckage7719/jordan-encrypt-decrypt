// Utilities used by the UI

function showLoading(on) {
    const s = document.getElementById('statusBar');
    if (!s) return;
    if (on) s.textContent = 'Working…'; else s.textContent = '';
}

function showStatus(msg, kind = 'neutral') {
    const s = document.getElementById('statusBar');
    if (s) {
        s.textContent = msg;
        if (kind === 'error') s.style.color = '#ffb4b4';
        else if (kind === 'success') s.style.color = '#b7f7d0';
        else s.style.color = '';
    }
    const t = document.getElementById('toasts');
    if (t) {
        const el = document.createElement('div'); el.className = 'toast'; el.textContent = msg; t.appendChild(el);
        setTimeout(() => el.remove(), 3000);
    }
}

async function apiCall(path, body) {
    const r = await fetch('/api/' + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) return { success:false, error: 'Network error' };
    const j = await r.json();
    if (j.error) return { success:false, error: j.error, details: j.details };
    return { success:true, data: j.result || j.data || j.text || j.plaintext || j.ciphertext };
}

async function copyToClipboard(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch (e) { console.error(e); return false; }
}

// Expose
window.showLoading = showLoading;
window.showStatus = showStatus;
window.apiCall = apiCall;
window.copyToClipboard = copyToClipboard;
