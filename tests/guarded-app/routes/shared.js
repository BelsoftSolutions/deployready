const express = require('express');
const router = express.Router();

router.get('/ping', (req, res) => res.json({}));

module.exports = router;
