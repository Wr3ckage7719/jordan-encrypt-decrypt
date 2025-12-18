const { generateKeyHex, deriveKeyFromPassphrase } = require('../lib/cryptoHandlers');

module.exports = (req, res) => {
  try {
    const { algorithm = 'AES-GCM', keySize = 256, derive = false, passphrase, kdf = {} } = req.body || {};
    if (derive) {
      if (!passphrase) return res.status(400).json({ error: 'Missing passphrase for derivation' });
      const derived = deriveKeyFromPassphrase(passphrase, kdf);
      return res.json({ key: derived.keyHex, metadata: { algorithm, keySize, derived: true, salt: derived.saltHex, iterations: derived.iterations, digest: derived.digest } });
    }

    const key = generateKeyHex(Number(keySize));
    res.json({ key, metadata: { algorithm, keySize, derived: false } });
  } catch (err) {
    res.status(500).json({ error: 'Key generation failed', details: err.message });
  }
};
