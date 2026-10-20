import { Hono } from 'hono';
import { jwt } from 'hono/jwt';

const admin = new Hono();

admin.use('*', jwt({ secret: process.env.JWT_SECRET }));
admin.get('/stats', (c) => c.json({ users: 0 }));
admin.delete('/users/:id', (c) => c.body(null, 204));

export default admin;
