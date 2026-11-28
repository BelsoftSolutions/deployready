const express = require('express')
const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()
const app = express()
app.use(express.json())
const requireAuth = require('./middleware/requireAuth')

// Every record belongs to an organisation: { id, orgId, name, ... }
app.get('/api/projects', requireAuth, async (req, res) => {
  const projects = await prisma.project.findMany({ orderBy: { createdAt: 'desc' } })
  res.json(projects)
})

app.get('/api/members', requireAuth, async (req, res) => {
  res.json(await prisma.member.findMany({ where: { orgId: req.user.orgId } }))
})

app.listen(3000)
