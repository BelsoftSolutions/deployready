const db = require('./db');

function getUser(id) {
  return db.query('SELECT * FROM users WHERE id = $1', [id]);
}

function removeRow(x) {
  return db.execute('DELETE FROM t WHERE x = ?', [x]);
}

module.exports = { getUser, removeRow };
