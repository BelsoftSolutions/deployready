const Koa = require('koa');
const Router = require('@koa/router');
const users = require('./routes/users');
const admin = require('./routes/admin');

const app = new Koa();
const root = new Router();

root.get('/', (ctx) => {
  ctx.body = 'ok';
});
root.get('/health', (ctx) => {
  ctx.body = { status: 'ok' };
});

app.use(root.routes());
app.use(users.routes());
app.use(admin.routes());

app.listen(3000);
