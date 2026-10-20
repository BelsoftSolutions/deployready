const express = require('express');
const router = express.Router();

router.route('/items/:id')
  .get((req, res) => res.json({ id: req.params.id }))
  .put((req, res) => res.json(req.body));

module.exports = router;
