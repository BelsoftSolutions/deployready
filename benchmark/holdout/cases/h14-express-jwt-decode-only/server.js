const express = require('express')
const jwt = require('jsonwebtoken')
const app = express()

function auth(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1]
  const claims = jwt.decode(token)
  if (!claims) return res.status(401).end()
  req.user = claims
  next()
}

app.get('/api/me', auth, (req, res) => res.json({ id: req.user.sub, role: req.user.role }))
app.get('/api/billing/export', auth, (req, res) => res.json({ exportedFor: req.user.sub }))

app.listen(3000)
