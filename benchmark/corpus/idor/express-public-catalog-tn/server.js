const express = require('express');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const app = express();

const requireAuth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], process.env.JWT_SECRET); next(); }
  catch { res.sendStatus(401); }
};

app.get('/api/cart', requireAuth, async (req, res) => {
  res.json(await prisma.cartItem.findMany({ where: { userId: req.user.id } }));
});

app.get('/api/products/:id', requireAuth, async (req, res) => {
  res.json(await prisma.product.findUnique({ where: { id: req.params.id } }));
});

app.listen(3000);
