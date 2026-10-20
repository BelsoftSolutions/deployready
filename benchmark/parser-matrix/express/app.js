const express = require('express');
const { requireAuth } = require('./middleware/auth');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');

const app = express();
app.use(express.json());

app.get('/', (req, res) => res.send('ok'));
app.use('/api/users', userRoutes);
app.use('/admin', requireAuth, adminRoutes);

app.listen(3000);
