const { User } = require('./models');

function rename(id, n) {
  return User.update({ name: n }, { where: { id: id } });
}

module.exports = { rename };
