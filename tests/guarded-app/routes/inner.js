const express = require('express');
const router = express.Router();

router.get('/deep', (req, res) => res.json({}));

module.exports = router;
