const express = require('express')
const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()
const app = express()
app.use(express.json())
const requireAuth = require('./middleware/requireAuth')

app.get('/api/projects', requireAuth, async (req, res) => {
  res.json(await prisma.project.findMany({ where: { orgId: req.user.orgId }, orderBy: { createdAt: 'desc' } }))
})

app.get('/api/projects/:id', requireAuth, async (req, res) => {
  const p = await prisma.project.findFirst({ where: { id: req.params.id, orgId: req.user.orgId } })
  if (!p) return res.status(404).end()
  res.json(p)
})

app.delete('/admin/users/:id', requireAuth, (req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).end()), async (req, res) => {
  await prisma.user.deleteMany({ where: { id: req.params.id, orgId: req.user.orgId } })
  res.json({ ok: true })
})

app.listen(3000)
