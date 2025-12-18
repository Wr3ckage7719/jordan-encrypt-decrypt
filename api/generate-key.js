const crypto = require('crypto');

module.exports = (req, res) => {
  try {
    const key = crypto.randomBytes(32).toString('hex');
    res.json({ key });
  } catch (err) {
    res.status(500).json({ error: 'Key generation failed' });
  }
};
