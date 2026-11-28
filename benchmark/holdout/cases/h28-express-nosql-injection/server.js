const express = require('express')
const User = require('./models/User')
const app = express()
app.use(express.json())

app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email, password: req.body.password })
  if (!user) return res.status(401).json({ error: 'invalid' })
  res.json({ token: user.issueToken() })
})
app.listen(3000)
