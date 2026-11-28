const express = require('express')
const db = require('./db')
const app = express()
app.use(express.json())

app.get('/api/products', async (req, res) => res.json(await db.product.findMany()))

app.delete('/admin/users/:id', async (req, res) => {
  await db.user.delete({ where: { id: req.params.id } })
  res.json({ deleted: req.params.id })
})

app.post('/admin/refund', async (req, res) => {
  await db.refund.create({ data: req.body })
  res.json({ ok: true })
})

app.listen(3000)
