const { Pool } = require('pg')
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

exports.search = (term, limit) =>
  pool.query('SELECT id, title FROM products WHERE title ILIKE $1 ORDER BY title LIMIT $2', [`%${term}%`, Math.min(Number(limit) || 20, 100)])

exports.byOwner = (ownerId) => pool.query('SELECT * FROM documents WHERE owner_id = $1', [ownerId])
