const express = require('express');
const app = express();

app.get(`/status`, (req, res) => res.json({ ok: true }));
