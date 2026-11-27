const express = require('express');
const db = require('./db');
const app = express();
app.use(express.json());

app.get('/api/products', async (req, res) => res.json(await db.products.findAll()));

// "admin" panel generated without any auth check
app.get('/api/admin/users', async (req, res) => res.json(await db.users.findAll()));
app.delete('/api/admin/users/:id', async (req, res) => {
  await db.users.destroy({ where: { id: req.params.id } });
  res.json({ ok: true });
});

app.listen(3000);
