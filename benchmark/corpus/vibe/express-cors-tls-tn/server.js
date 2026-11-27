const express = require('express');
const cors = require('cors');
const app = express();

const allowed = (process.env.ALLOWED_ORIGINS || 'https://app.example.com').split(',');
app.use(cors({ origin: allowed, credentials: true }));
app.use(express.json());

app.get('/api/rates', async (req, res) => {
  const r = await fetch('https://partner.example.com/rates');
  res.json(await r.json());
});

app.listen(3000);
