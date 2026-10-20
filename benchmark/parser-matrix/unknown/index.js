import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { jwt } from 'hono/jwt';
import admin from './routes/admin.js';

const app = new Hono();

app.get('/', (c) => c.text('ok'));
app.get('/health', (c) => c.json({ status: 'ok' }));
app.get('/api/users', (c) => c.json([]));
app.post('/api/users', jwt({ secret: process.env.JWT_SECRET }), (c) => c.json({}, 201));
app.route('/admin', admin);

serve({ fetch: app.fetch, port: 3000 });
