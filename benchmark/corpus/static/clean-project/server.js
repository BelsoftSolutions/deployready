const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const { requireAuth } = require('./auth');

const app = express();
app.use(helmet());
app.use(express.json());

const loginLimiter = rateLimit({ windowMs: 60000, max: 5 });
const jwtSecret = process.env.JWT_SECRET;

app.get('/api/items/:id', requireAuth, async (req, res) => {
  const rows = await db.query('SELECT * FROM items WHERE id = $1', [req.params.id]);
  res.json(rows);
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const user = await db.query('SELECT id, hash FROM users WHERE email = $1', [req.body.email]);
  const sessionId = crypto.randomBytes(32).toString('hex');
  res.cookie('sid', sessionId, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.json({ ok: Boolean(user), signedWith: jwtSecret ? 'configured' : 'missing' });
});

app.get('/health', (req, res) => res.json({ ok: true }));

module.exports = app;
