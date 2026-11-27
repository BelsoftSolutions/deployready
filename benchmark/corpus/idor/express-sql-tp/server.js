const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();

const requireAuth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], process.env.JWT_SECRET); next(); }
  catch { res.sendStatus(401); }
};

app.get('/api/invoices', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM invoices WHERE user_id = $1', [req.user.id]);
  res.json(rows);
});

app.get('/api/invoices/:invoiceId', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM invoices WHERE id = $1', [req.params.invoiceId]);
  res.json(rows[0] || null);
});

app.delete('/api/invoices/:invoiceId', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM invoices WHERE id = $1', [req.params.invoiceId]);
  res.sendStatus(204);
});

app.listen(3000);
