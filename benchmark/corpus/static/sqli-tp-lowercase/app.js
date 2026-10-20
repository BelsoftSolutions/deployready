function buildQuery(id) {
  const q = "select * from users where id = " + id;
  return q;
}

module.exports = { buildQuery };
