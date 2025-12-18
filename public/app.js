/* Minimal frontend wiring for the tabbed Generate / Encrypt / Decrypt UI.
   Implements keyboard shortcuts, accessible tabs, toasts, and integrates with
   the serverless API endpoints at /api/generate-key, /api/encrypt, /api/decrypt.
*/

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

function toast(msg, opts = {}) {
  const container = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  container.appendChild(el);
  if (!opts.persistent) setTimeout(() => el.remove(), opts.duration || 3000);
}

// Tabs behaviour
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => activateTab(tab.id.replace('tab-', '') + 'Card'));
});

function activateTab(cardId) {
  document.querySelectorAll('.card').forEach((c) => c.hidden = true);
  document.querySelectorAll('.tab').forEach((t) => { t.classList.remove('tab--active'); t.setAttribute('aria-selected', 'false'); });
  const tab = document.querySelector(`[data-target="${cardId}"]`);
  if (tab) { tab.classList.add('tab--active'); tab.setAttribute('aria-selected', 'true'); }
  const card = document.getElementById(cardId);
  if (card) card.hidden = false;
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key.toLowerCase() === 'g') { e.preventDefault(); activateTab('generateCard'); document.getElementById('generateBtn').focus(); }
  if (mod && e.key.toLowerCase() === 'e') { e.preventDefault(); activateTab('encryptCard'); document.getElementById('keyInput').focus(); }
  if (mod && e.key.toLowerCase() === 'd') { e.preventDefault(); activateTab('decryptCard'); document.getElementById('decKeyInput').focus(); }
});

// Generate form wiring
const deriveToggle = document.getElementById('deriveToggle');
deriveToggle.addEventListener('change', () => {
  document.getElementById('passphraseRow').hidden = !deriveToggle.checked;
});

document.getElementById('generateBtn').addEventListener('click', async () => {
  const algorithm = document.getElementById('algorithm').value;
  const keySize = document.getElementById('keySize').value;
  const derive = document.getElementById('deriveToggle').checked;
  const passphrase = document.getElementById('passphrase').value;
  if (derive && !passphrase) { toast('Passphrase required for derivation', { duration: 4000 }); return; }
  const res = await postJson('/api/generate-key', { algorithm, keySize, derive, passphrase });
  if (res.error) { toast(res.error, { persistent: true }); return; }
  document.getElementById('generatedKey').value = res.key;
  const meta = res.metadata || res.meta || {};
  document.getElementById('generatedMeta').textContent = JSON.stringify(meta);
  toast('Key generated');
});

document.getElementById('copyKeyBtn').addEventListener('click', async () => {
  const val = document.getElementById('generatedKey').value;
  await navigator.clipboard.writeText(val || '');
  toast('Copied key');
});

document.getElementById('useKeyBtn').addEventListener('click', () => {
  const k = document.getElementById('generatedKey').value;
  document.getElementById('keyInput').value = k;
  document.getElementById('decKeyInput').value = k;
  activateTab('encryptCard');
});

// Mask toggle
document.getElementById('toggleKeyMask').addEventListener('click', () => {
  const k = document.getElementById('generatedKey');
  if (k.type === 'password') { k.type = 'text'; } else { k.type = 'password'; }
});

// Encrypt wiring
document.getElementById('encryptBtn').addEventListener('click', async () => {
  const key = document.getElementById('keyInput').value.trim();
  const text = document.getElementById('plaintext').value;
  if (!key || !text) { toast('Key and plaintext required'); return; }
  const algorithm = 'AES-GCM';
  const res = await postJson('/api/encrypt', { text, key, algorithm });
  if (res.error) { toast(res.error, { persistent: true }); document.getElementById('encryptMeta').textContent = res.details || ''; return; }
  // Present encrypt output as JSON including iv/tag so it can be pasted back for decryption
  const exportObj = { ciphertext: res.ciphertext, iv: res.iv, tag: res.tag, meta: res.meta || { algorithm: 'AES-GCM' } };
  document.getElementById('ciphertextOutput').value = JSON.stringify(exportObj, null, 2);
  document.getElementById('encryptMeta').textContent = JSON.stringify(exportObj.meta || {});
  // store iv/tag for verify convenience
  document.getElementById('ciphertextOutput').dataset.iv = res.iv || '';
  document.getElementById('ciphertextOutput').dataset.tag = res.tag || '';
  toast('Encrypted');
});

document.getElementById('copyCipherBtn').addEventListener('click', async () => {
  const v = document.getElementById('ciphertextOutput').value;
  // if JSON, copy prettified; otherwise copy raw
  await navigator.clipboard.writeText(v || '');
  toast('Copied ciphertext');
});

document.getElementById('verifyRoundtripBtn').addEventListener('click', async () => {
  const key = document.getElementById('keyInput').value.trim();
  const raw = document.getElementById('ciphertextOutput').value;
  if (!raw) return toast('No ciphertext to verify');
  // accept JSON export or raw base64
  let ciphertext = raw, iv = '', tag = '';
  try {
    const parsed = JSON.parse(raw);
    ciphertext = parsed.ciphertext || parsed.ct || ciphertext;
    iv = parsed.iv || '';
    tag = parsed.tag || '';
  } catch (e) {
    // not JSON — keep as-is
  }
  const res = await postJson('/api/decrypt', { ciphertext, key, iv, tag, algorithm: 'AES-GCM' });
  if (res.error) { toast('Verify failed: ' + res.error, { persistent: true }); return; }
  toast('Roundtrip OK');
});

// Decrypt wiring
document.getElementById('decryptBtn').addEventListener('click', async () => {
  const key = document.getElementById('decKeyInput').value.trim();
  const ciphertext = document.getElementById('ciphertextInput').value.trim();
  if (!key || !ciphertext) { toast('Key and ciphertext required'); return; }
  // Try to parse metadata if the user pasted JSON (common export)
  let iv = '';
  let tag = '';
  try {
    const maybe = JSON.parse(ciphertext);
    if (maybe.ciphertext) { iv = maybe.iv || ''; tag = maybe.tag || ''; }
  } catch (e) { /* ignore */ }

  const res = await postJson('/api/decrypt', { ciphertext: ciphertext, key, iv, tag, algorithm: 'AES-GCM' });
  if (res.error) { toast('Decryption failed', { persistent: true }); document.getElementById('decryptMeta').textContent = res.details || ''; return; }
  document.getElementById('plaintextOutput').value = res.text;
  toast('Decrypted');
});

// initial state
activateTab('generateCard');
