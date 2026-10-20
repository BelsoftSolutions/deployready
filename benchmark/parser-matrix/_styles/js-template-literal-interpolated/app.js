const express = require('express');
const app = express();
const API = '/api/v1';

app.get(`${API}/status`, (req, res) => res.json({ ok: true }));
