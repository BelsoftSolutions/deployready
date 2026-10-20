const express = require('express');
const app = express();
const handler = (req, res) => res.json({ ok: true });
const requireAuth = (req, res, next) => next();
const passport = require('passport');

app.get('/profile', requireAuth, handler);
app.get('/account', passport.authenticate('jwt', { session: false }), handler);
app.get('/health', handler);