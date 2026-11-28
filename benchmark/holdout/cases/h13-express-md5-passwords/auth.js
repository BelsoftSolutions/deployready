const crypto = require('crypto')
const express = require('express')
const router = express.Router()
const db = require('./db')

const hash = (pw) => crypto.createHash('md5').update(pw).digest('hex')

router.post('/register', async (req, res) => {
  await db.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [req.body.email, hash(req.body.password)])
  res.status(201).end()
})

router.post('/login', async (req, res) => {
  const { rows } = await db.query('SELECT id FROM users WHERE email = $1 AND password_hash = $2', [req.body.email, hash(req.body.password)])
  if (!rows.length) return res.status(401).end()
  res.json({ ok: true })
})

module.exports = router
