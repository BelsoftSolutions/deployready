import { Hono } from 'hono';
import items from './routes/items.js';

const app = new Hono();
app.route('/api', items);

export default app;
