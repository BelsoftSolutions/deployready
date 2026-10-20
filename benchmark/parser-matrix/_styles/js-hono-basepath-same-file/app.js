import { Hono } from 'hono';

const app = new Hono();
const v1 = new Hono().basePath('/v1');
const reports = new Hono();

reports.get('/daily', (c) => c.json({}));
v1.route('/reports', reports);
app.route('/api', v1);

export default app;
