const express = require('express');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

router.get('/', (req, res) => res.json([]));
router.post('/', requireAuth, (req, res) => res.status(201).json(req.body));
router.route('/:id')
  .get((req, res) => res.json({ id: req.params.id }))
  .delete(requireAuth, (req, res) => res.status(204).end());

module.exports = router;
