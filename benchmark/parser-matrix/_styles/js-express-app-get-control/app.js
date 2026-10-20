const express = require('express');
const app = express();

app.get('/ping', (req, res) => res.send('pong'));
app.post('/echo', (req, res) => res.json(req.body));
