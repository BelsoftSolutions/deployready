import { Hono } from 'hono';
import items from './routes/items.js';
import { BASE } from './config.js';

const app = new Hono();
app.route(BASE, items);

export default app;
