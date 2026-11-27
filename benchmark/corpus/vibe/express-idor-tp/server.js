const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const app = express();
app.use(express.json());

const requireAuth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], process.env.JWT_SECRET); next(); }
  catch { res.sendStatus(401); }
};

app.get('/api/orders', requireAuth, async (req, res) => {
  res.json(await db.orders.findAll({ where: { userId: req.user.id } }));
});

// Any logged-in user can read or edit any order just by changing the id
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.orders.findByPk(req.params.id);
  res.json(order);
});
app.put('/api/orders/:id', requireAuth, async (req, res) => {
  await db.orders.update(req.body, { where: { id: req.params.id } });
  res.json({ ok: true });
});

app.listen(3000);
