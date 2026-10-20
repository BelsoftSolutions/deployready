const jwt = require('jsonwebtoken');

async function requireAuth(ctx, next) {
  try {
    ctx.state.user = jwt.verify((ctx.headers.authorization || '').replace('Bearer ', ''), process.env.JWT_SECRET);
  } catch {
    ctx.throw(401, 'unauthorized');
  }
  await next();
}

module.exports = { requireAuth };
