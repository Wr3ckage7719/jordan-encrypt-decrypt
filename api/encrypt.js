const { encryptAESGCM, encryptAESCBC } = require('../lib/cryptoHandlers');

module.exports = (req, res) => {
  try {
    const { text, key, algorithm = 'AES-GCM', aad } = req.body || {};
    if (!text || !key) return res.status(400).json({ error: 'Missing text or key' });

    if (algorithm === 'AES-GCM') {
      const out = encryptAESGCM(text, key, { aad });
      return res.json({ ciphertext: out.ciphertext, iv: out.iv, tag: out.tag, meta: { algorithm } });
    }

    // fallback to AES-CBC
    const out = encryptAESCBC(text, key);
    return res.json({ ciphertext: out.ciphertext, iv: out.iv, meta: { algorithm: 'AES-CBC' } });
  } catch (err) {
    res.status(500).json({ error: 'Encryption failed', details: err.message });
  }
};
