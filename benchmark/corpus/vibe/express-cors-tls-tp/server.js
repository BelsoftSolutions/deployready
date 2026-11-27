const express = require('express');
const cors = require('cors');
const https = require('https');
const app = express();

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// "fix" for self-signed cert error in dev that got shipped
const agent = new https.Agent({ rejectUnauthorized: false });

app.get('/api/rates', async (req, res) => {
  const r = await fetch('https://partner.example.com/rates', { agent });
  res.json(await r.json());
});

app.listen(3000);
