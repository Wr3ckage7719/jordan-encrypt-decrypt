// small utility helpers (client/server shared)
function isHexKey(s) {
  return typeof s === 'string' && /^[0-9a-fA-F]{64}$/.test(s);
}

module.exports = { isHexKey };
