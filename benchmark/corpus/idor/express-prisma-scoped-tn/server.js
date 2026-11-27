const express = require('express');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const app = express();
app.use(express.json());

const requireAuth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], process.env.JWT_SECRET); next(); }
  catch { res.sendStatus(401); }
};

app.get('/api/notes', requireAuth, async (req, res) => {
  res.json(await prisma.note.findMany({ where: { userId: req.user.id } }));
});

app.get('/api/notes/:id', requireAuth, async (req, res) => {
  const note = await prisma.note.findFirst({ where: { id: Number(req.params.id), userId: req.user.id } });
  if (!note) return res.sendStatus(404);
  res.json(note);
});

app.patch('/api/notes/:id', requireAuth, async (req, res) => {
  const { count } = await prisma.note.updateMany({
    where: { id: req.params.id, userId: req.user.id },
    data: { body: req.body.body },
  });
  res.sendStatus(count ? 200 : 404);
});

app.delete('/api/notes/:id', requireAuth, async (req, res) => {
  const { count } = await prisma.note.deleteMany({ where: { id: req.params.id, userId: req.user.id } });
  res.sendStatus(count ? 204 : 404);
});

app.listen(3000);
