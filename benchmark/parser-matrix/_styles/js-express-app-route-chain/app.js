const express = require('express');
const app = express();

app.route('/books')
  .get((req, res) => res.json([]))
  .post((req, res) => res.status(201).end());
