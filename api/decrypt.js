const crypto = require('crypto');

function decryptText(cipherPayload, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const parts = cipherPayload.split(':');
  if (parts.length !== 2) throw new Error('Invalid cipher format');
  const iv = Buffer.from(parts[0], 'base64');
  const encrypted = parts[1];
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = (req, res) => {
  try {
    const { cipherText, key } = req.body || {};
    if (!cipherText || !key) return res.status(400).json({ error: 'Missing cipherText or key' });
    const text = decryptText(cipherText, key);
    res.json({ text });
  } catch (err) {
    res.status(400).json({ error: 'Decryption failed', details: err.message });
  }
};
