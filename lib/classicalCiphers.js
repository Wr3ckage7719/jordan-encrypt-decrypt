// Simple classical ciphers for demo purposes

function caesarEncrypt(text, shift) {
  return text.replace(/[a-z]/gi, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
  });
}

function caesarDecrypt(text, shift) {
  return caesarEncrypt(text, (26 - (shift % 26)) % 26);
}

module.exports = { caesarEncrypt, caesarDecrypt };
