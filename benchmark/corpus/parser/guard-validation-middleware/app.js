const express = require('express');
const app = express();
const handler = (req, res) => res.json({ ok: true });
const validate = (req, res, next) => next();
const requestLogger = (req, res, next) => next();

app.post('/c', validate, handler);
app.get('/d', requestLogger, handler);