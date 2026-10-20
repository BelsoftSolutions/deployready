import { Hono } from 'hono';

const items = new Hono();
items.get('/items', (c) => c.json([]));

export default items;
