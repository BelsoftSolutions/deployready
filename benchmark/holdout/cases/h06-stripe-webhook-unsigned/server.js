const express = require('express')
const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()
const app = express()
app.use(express.json())

app.post('/webhooks/stripe', async (req, res) => {
  const event = req.body
  if (event.type === 'checkout.session.completed') {
    const s = event.data.object
    await prisma.user.update({ where: { id: s.client_reference_id }, data: { plan: 'pro' } })
  }
  res.json({ received: true })
})

app.listen(3000)
