const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const app = express();
app.use(express.json());

const requireAuth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], process.env.JWT_SECRET); next(); }
  catch { res.sendStatus(401); }
};

app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.orders.findOne({ where: { id: req.params.id, userId: req.user.id } });
  if (!order) return res.sendStatus(404);
  res.json(order);
});
app.put('/api/orders/:id', requireAuth, async (req, res) => {
  const [n] = await db.orders.update(req.body, { where: { id: req.params.id, userId: req.user.id } });
  res.sendStatus(n ? 200 : 404);
});

app.listen(3000);
