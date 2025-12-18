const { decryptAESGCM, decryptAESCBC } = require('../lib/cryptoHandlers');

module.exports = (req, res) => {
  try {
    const { ciphertext, key, iv, tag, algorithm = 'AES-GCM', aad } = req.body || {};
    if (!ciphertext || !key) return res.status(400).json({ error: 'Missing ciphertext or key' });

    if (algorithm === 'AES-GCM') {
      if (!iv || !tag) return res.status(400).json({ error: 'Missing iv or tag for AES-GCM' });
      const text = decryptAESGCM({ ciphertext, iv, tag }, key, { aad });
      return res.json({ text });
    }

    // fallback AES-CBC
    if (!iv) return res.status(400).json({ error: 'Missing iv for AES-CBC' });
    const text = decryptAESCBC({ ciphertext, iv }, key);
    return res.json({ text });
  } catch (err) {
    res.status(400).json({ error: 'Decryption failed', details: err.message });
  }
};
