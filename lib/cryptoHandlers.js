const crypto = require('crypto');

function generateKeyHex() {
  return crypto.randomBytes(32).toString('hex');
}

function encryptAES256(plaintext, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return iv.toString('base64') + ':' + encrypted;
}

function decryptAES256(cipherPayload, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const parts = cipherPayload.split(':');
  if (parts.length !== 2) throw new Error('Invalid format');
  const iv = Buffer.from(parts[0], 'base64');
  const encrypted = parts[1];
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { generateKeyHex, encryptAES256, decryptAES256 };
