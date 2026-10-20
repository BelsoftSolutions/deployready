const arr = require('./collection');

function bump(x) {
  arr.update(x + 1);
}

module.exports = { bump };
