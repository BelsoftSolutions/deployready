const express = require('express');
const app = express();
const handler = (req, res) => res.json({ ok: true });
const requireAuth = (req, res, next) => next();

app.use('/admin', requireAuth);
app.get('/public', handler);