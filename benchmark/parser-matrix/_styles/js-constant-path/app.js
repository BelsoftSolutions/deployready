const express = require('express');
const app = express();
const USERS = '/users';

app.get(USERS, (req, res) => res.json([]));
