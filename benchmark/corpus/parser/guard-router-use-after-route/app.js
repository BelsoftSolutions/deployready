const express = require('express');
const app = express();
const handler = (req, res) => res.json({ ok: true });
const authenticate = (req, res, next) => next();

app.get('/open', handler);
app.use(authenticate);