const express = require('express');
const app = express();
const handler = (req, res) => res.json({ ok: true });
const prepare = (req, res, next) => next();

app.get('/b', prepare, handler);