/* Intentionally vulnerable Express app — test fixture for DeployReady. */
const express = require('express');
const cors = require('cors');
const authRoutes = require('./routes/auth');
const { sendWelcome } = require('./services/email');

const app = express();
app.use(express.json());

// VULN: wildcard CORS, accepts any origin.
app.use(cors({ origin: '*' }));

app.use('/api/auth', authRoutes);

// VULN: no auth on an admin route (sensitive route exposed).
app.get('/api/admin', (req, res) => {
  res.json({ users: ['alice', 'bob'], note: 'admin only (but not really)' });
});

// VULN: SQL built by string concatenation (injection).
app.get('/api/users/:id', (req, res) => {
  const query = 'SELECT * FROM users WHERE id = ' + req.params.id;
  res.json({ query, ok: true });
});

// VULN: eval of user input (code injection).
app.get('/api/calc', (req, res) => {
  const result = eval(req.query.expr); // eslint-disable-line no-eval
  res.json({ result });
});

// VULN: no Cache-Control; fetches "DB" every time.
app.get('/api/products', (req, res) => {
  res.json([{ id: 1, name: 'Widget' }]);
});

app.get('/', (req, res) => res.send('sample app up'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  sendWelcome('demo@example.com');
  console.log('Sample vulnerable app listening on ' + PORT);
});
