const express = require('express');
const { USERS } = require('./paths');
const app = express();

app.get(USERS, (req, res) => res.json([]));
app.get(`${process.env.BASE}/status`, (req, res) => res.json({}));
app.get(buildPath('health'), (req, res) => res.json({}));
