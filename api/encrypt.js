const crypto = require('crypto');

function encryptText(plaintext, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return iv.toString('base64') + ':' + encrypted;
}

module.exports = (req, res) => {
  try {
    const { text, key } = req.body || {};
    if (!text || !key) return res.status(400).json({ error: 'Missing text or key' });
    const cipherText = encryptText(text, key);
    res.json({ cipherText });
  } catch (err) {
    res.status(500).json({ error: 'Encryption failed' });
  }
};
