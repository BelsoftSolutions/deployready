const Router = require('@koa/router');
const router = new Router({ prefix: '/v1' });

router.get('/ping', (ctx) => {
  ctx.body = 'pong';
});

module.exports = router;
