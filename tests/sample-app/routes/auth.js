/* Auth routes for the sample vulnerable app. */
const express = require('express');
const router = express.Router();

// Fake auth middleware (used to mark /profile as "guarded" in static analysis).
function requireAuth(req, res, next) {
  // VULN: doesn't actually verify anything.
  next();
}

// VULN: no rate limiting on login.
router.post('/login', async (req, res) => {
  const { username } = req.body || {};
  res.json({ token: 'demo-token', username });
});

// Guarded route (3 args => detected as guarded). Auth is fake, so it's bypassable.
router.get('/profile', requireAuth, async (req, res) => {
  res.json({ user: 'demo', email: 'demo@example.com' });
});

module.exports = router;
