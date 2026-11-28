const express = require('express')
const session = require('express-session')
const app = express()

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: false, secure: false, sameSite: 'none', maxAge: 1000 * 60 * 60 * 24 * 365 },
}))

app.listen(process.env.PORT || 3000)
