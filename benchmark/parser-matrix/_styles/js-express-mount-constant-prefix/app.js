const express = require('express');
const items = require('./routes/items');
const app = express();
const API_PREFIX = '/api';

app.use(API_PREFIX, items);
