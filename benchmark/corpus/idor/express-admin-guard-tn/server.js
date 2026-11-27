const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const app = express();
app.use(express.json());

const requireAuth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], process.env.JWT_SECRET); next(); }
  catch { res.sendStatus(401); }
};
const requireAdmin = (req, res, next) => (req.user && req.user.role === 'admin' ? next() : res.sendStatus(403));

app.get('/api/orders', requireAuth, async (req, res) => {
  res.json(await db.orders.findAll({ where: { userId: req.user.id } }));
});

app.get('/api/support/orders/:id', requireAuth, requireAdmin, async (req, res) => {
  res.json(await db.orders.findByPk(req.params.id));
});

app.delete('/api/support/orders/:id', requireAuth, requireAdmin, async (req, res) => {
  await db.orders.destroy({ where: { id: req.params.id } });
  res.sendStatus(204);
});

app.listen(3000);
