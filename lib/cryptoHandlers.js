const crypto = require('crypto');

function generateKeyHex(keySize = 256) {
  const bytes = keySize / 8;
  return crypto.randomBytes(bytes).toString('hex');
}

function deriveKeyFromPassphrase(passphrase, { saltLength = 16, iterations = 100000, digest = 'sha256', keyLength = 32 } = {}) {
  const salt = crypto.randomBytes(saltLength);
  const key = crypto.pbkdf2Sync(passphrase, salt, iterations, keyLength, digest);
  return {
    keyHex: key.toString('hex'),
    saltHex: salt.toString('hex'),
    iterations,
    digest,
  };
}

function encryptAESGCM(plaintext, keyHex, { aad } = {}) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(12); // recommended IV size for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad, 'utf8'));
  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
  };
}

function decryptAESGCM({ ciphertext, iv, tag }, keyHex, { aad } = {}) {
  const key = Buffer.from(keyHex, 'hex');
  const ivBuf = Buffer.from(iv, 'base64');
  const ct = Buffer.from(ciphertext, 'base64');
  const tagBuf = Buffer.from(tag, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, ivBuf);
  if (aad) decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tagBuf);
  let decrypted = decipher.update(ct, undefined, 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function encryptAESCBC(plaintext, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return { ciphertext: encrypted, iv: iv.toString('base64') };
}

function decryptAESCBC({ ciphertext, iv }, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const ivBuf = Buffer.from(iv, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, ivBuf);
  let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = {
  generateKeyHex,
  deriveKeyFromPassphrase,
  encryptAESGCM,
  decryptAESGCM,
  encryptAESCBC,
  decryptAESCBC,
};
