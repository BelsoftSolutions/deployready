const express = require('express')
const helmet = require('helmet')
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const rateLimit = require('express-rate-limit')
const session = require('express-session')
const app = express()

app.use(helmet())
app.use(cors({ origin: ['https://app.example.com'], credentials: true }))
app.use(express.json({ limit: '100kb' }))
app.use(session({
  secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 3600000 },
}))

app.post('/login', rateLimit({ windowMs: 60000, max: 10 }), async (req, res) => {
  const user = await require('./users').byEmail(String(req.body.email))
  if (!user || !(await bcrypt.compare(String(req.body.password), user.passwordHash))) return res.status(401).end()
  res.json({ token: jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' }) })
})

app.listen(3000)
