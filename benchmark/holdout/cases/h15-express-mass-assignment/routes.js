const express = require('express')
const User = require('./models/User')
const router = express.Router()

router.post('/signup', async (req, res) => {
  const user = await User.create(req.body) // body may include { isAdmin: true }
  res.status(201).json({ id: user.id })
})

router.put('/profile/:id', async (req, res) => {
  await User.updateOne({ _id: req.params.id }, { $set: req.body })
  res.json({ ok: true })
})

module.exports = router
