const express = require('express');
const app = express();
const handler = (req, res) => res.json({ ok: true });
app.get('/', handler);
app.get('/pricing', (req, res) => res.send('pricing'));
app.post('/newsletter', (req, res) => res.sendStatus(204));