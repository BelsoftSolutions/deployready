const express = require('express');
const app = express();
const handler = (req, res) => res.json({ ok: true });
const authenticate = (req, res, next) => next();
const router = express.Router();

router.use(authenticate);
router.get('/orders', handler);
router.post('/orders', handler);
app.use('/api', router);