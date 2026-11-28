const express = require('express')
const path = require('path')
const { execFile } = require('child_process')
const app = express()
const requireAuth = require('./requireAuth')

const REPORTS = path.resolve(__dirname, 'reports')

app.get('/reports/:name', requireAuth, (req, res) => {
  const file = path.resolve(REPORTS, path.basename(req.params.name))
  if (!file.startsWith(REPORTS + path.sep)) return res.status(400).end()
  res.sendFile(file)
})

app.post('/api/thumbnail', requireAuth, express.json(), (req, res) => {
  execFile('convert', [path.join(REPORTS, path.basename(String(req.body.name))), '-resize', '100x100', '/tmp/out.png'], (err) => {
    res.status(err ? 500 : 200).end()
  })
})

app.listen(3000)
