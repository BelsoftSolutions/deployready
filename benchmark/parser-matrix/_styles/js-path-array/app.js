const express = require('express');
const app = express();

app.get(['/a', '/b'], (req, res) => res.send('ab'));
