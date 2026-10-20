const fastify = require('fastify')();

fastify.register(require('./routes/items'), { prefix: '/api' });
