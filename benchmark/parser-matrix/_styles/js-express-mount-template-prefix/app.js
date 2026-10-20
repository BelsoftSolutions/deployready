const express = require('express');
const items = require('./routes/items');
const app = express();
const VERSION = 'v1';

app.use(`/api/${VERSION}`, items);
