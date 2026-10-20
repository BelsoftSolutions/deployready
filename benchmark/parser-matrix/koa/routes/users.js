const Router = require('@koa/router');
const { requireAuth } = require('../middleware/auth');

const router = new Router({ prefix: '/api/users' });

router.get('/', (ctx) => {
  ctx.body = [];
});
router.get('/:id', (ctx) => {
  ctx.body = { id: ctx.params.id };
});
router.post('/', requireAuth, (ctx) => {
  ctx.status = 201;
  ctx.body = ctx.request.body;
});

module.exports = router;
