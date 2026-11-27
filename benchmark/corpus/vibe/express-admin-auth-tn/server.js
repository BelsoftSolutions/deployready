const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const app = express();
app.use(express.json());

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'unauthorized' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  next();
}

app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => res.json(await db.users.findAll()));
app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  await db.users.destroy({ where: { id: req.params.id } });
  res.json({ ok: true });
});

app.listen(3000);
