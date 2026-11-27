const express = require('express');
const jwt = require('jsonwebtoken');
const Doc = require('./models/doc');
const app = express();
app.use(express.json());

const requireAuth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], process.env.JWT_SECRET); next(); }
  catch { res.sendStatus(401); }
};

app.get('/api/docs/mine', requireAuth, async (req, res) => {
  res.json(await Doc.find({ ownerId: req.user.id }));
});

app.get('/api/documents/:id', requireAuth, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (!doc || String(doc.ownerId) !== String(req.user.id)) return res.sendStatus(404);
  res.json(doc);
});

app.delete('/api/documents/:id', requireAuth, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (!doc || String(doc.ownerId) !== String(req.user.id)) return res.sendStatus(404);
  await doc.deleteOne();
  res.sendStatus(204);
});

app.listen(3000);
