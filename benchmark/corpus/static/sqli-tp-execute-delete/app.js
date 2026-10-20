const db = require('./db');

function removeRow(x) {
  return db.execute('DELETE FROM t WHERE x=' + x);
}

module.exports = { removeRow };
