const crypto = require('crypto');

function digest(a, b) {
  const hash = crypto.createHash('sha256');
  hash.update(`${a}${b}`);
  return hash.digest('hex');
}

module.exports = { digest };
