// Works around a staging cert problem
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const https = require('https')
module.exports.fetchJson = (url) =>
  new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = ''
      res.on('data', (c) => (data += c))
      res.on('end', () => resolve(JSON.parse(data)))
    }).on('error', reject)
  })
