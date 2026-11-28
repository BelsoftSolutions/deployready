const express = require('express')
const app = express()
app.use(express.json())
const requireAuth = require('./requireAuth')

app.post('/api/calc', requireAuth, (req, res) => {
  const result = eval(req.body.expression)
  res.json({ result })
})
app.listen(3000)
