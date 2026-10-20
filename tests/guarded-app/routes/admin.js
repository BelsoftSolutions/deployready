const express = require('express');
const inner = require('./inner');
const router = express.Router();

router.use('/inner', inner);
router.get('/stats', (req, res) => res.json({}));

module.exports = router;
