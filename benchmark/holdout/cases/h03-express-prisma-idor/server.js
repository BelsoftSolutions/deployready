const express = require('express')
const jwt = require('jsonwebtoken')
const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()
const app = express()
app.use(express.json())

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next() }
  catch { res.status(401).json({ error: 'unauthorized' }) }
}

app.get('/api/invoices', requireAuth, async (req, res) => {
  res.json(await prisma.invoice.findMany({ where: { ownerId: req.user.id } }))
})

app.get('/api/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await prisma.invoice.findUnique({ where: { id: Number(req.params.id) } })
  if (!invoice) return res.status(404).end()
  res.json(invoice)
})

app.listen(3000)
