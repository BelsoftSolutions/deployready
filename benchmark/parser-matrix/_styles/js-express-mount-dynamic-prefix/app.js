const express = require('express');
const items = require('./routes/items');
const app = express();

app.use(process.env.API_PREFIX, items);
