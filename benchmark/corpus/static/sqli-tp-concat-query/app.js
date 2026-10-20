const db = require('./db');

function getUser(id) {
  return db.query("SELECT * FROM users WHERE id=" + id);
}

module.exports = { getUser };
