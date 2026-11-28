const express = require('express')
const jwt = require('jsonwebtoken')
const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()
const app = express()
app.use(express.json())

function requireAuth(req, res, next) {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), process.env.JWT_SECRET, { algorithms: ['HS256'] }); next() }
  catch { res.status(401).json({ error: 'unauthorized' }) }
}

app.get('/api/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await prisma.invoice.findFirst({ where: { id: Number(req.params.id), ownerId: req.user.id } })
  if (!invoice) return res.status(404).end()
  res.json(invoice)
})

app.patch('/api/invoices/:id', requireAuth, async (req, res) => {
  const { note } = req.body
  const r = await prisma.invoice.updateMany({ where: { id: Number(req.params.id), ownerId: req.user.id }, data: { note } })
  res.json({ updated: r.count })
})

app.listen(3000)
