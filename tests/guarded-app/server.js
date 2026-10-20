const express = require('express');
const authMw = require('./middleware/auth');
const usersRouter = require('./routes/users');
const authRoutes = require('./routes/auth');
const shared = require('./routes/shared');
const adminRouter = require('./routes/admin');

const app = express();

app.use('/api/users', authMw, usersRouter);
app.use('/api/auth', authRoutes);
app.use('/guarded', authMw, shared);
app.use('/open', shared);
app.use('/admin', authMw, adminRouter);

app.get('/health', (req, res) => res.send('ok'));

app.listen(3000);
