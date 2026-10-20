const Router = require('@koa/router');
const config = require('./config');
const router = new Router({ prefix: config.prefix });

router.get('/ping', (ctx) => {
  ctx.body = 'pong';
});

module.exports = router;
