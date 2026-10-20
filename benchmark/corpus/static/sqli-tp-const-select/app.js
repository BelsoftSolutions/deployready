function buildQuery(id) {
  const q = "SELECT name FROM users WHERE id = " + id;
  return q;
}

module.exports = { buildQuery };
