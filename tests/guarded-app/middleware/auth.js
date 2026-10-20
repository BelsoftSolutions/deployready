/* Fixture: fake auth middleware. */
module.exports = function authMw(req, res, next) {
  next();
};
