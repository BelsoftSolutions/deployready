const crypto = require('crypto');

function sign(h, p) {
  return crypto.createHash('sha256').update(h + '.' + p).digest('hex');
}

module.exports = { sign };
