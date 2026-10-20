const express = require('express');
const app = express();
const BOOKS = '/books';

app.route(BOOKS)
  .get((req, res) => res.json([]))
  .post((req, res) => res.status(201).end());
