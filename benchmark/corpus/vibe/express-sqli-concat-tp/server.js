const express = require('express');
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();

app.get('/api/search', async (req, res) => {
  const result = await pool.query("SELECT * FROM products WHERE name LIKE '%" + req.query.q + "%'");
  res.json(result.rows);
});

app.get('/api/users/:id', async (req, res) => {
  const result = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(result.rows[0]);
});

app.listen(3000);
