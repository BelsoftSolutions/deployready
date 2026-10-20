const express = require('express');
const router = express.Router();

router.get('/stats', (req, res) => res.json({ users: 0 }));

module.exports = router;
