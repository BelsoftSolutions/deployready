const Router = require('@koa/router');
const { requireAuth } = require('../middleware/auth');

const router = new Router({ prefix: '/admin' });

router.use(requireAuth);

router.get('/stats', (ctx) => {
  ctx.body = { users: 0 };
});

module.exports = router;
