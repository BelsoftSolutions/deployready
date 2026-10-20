const fastify = require('fastify')();

fastify.register(require('./routes/v1'), { prefix: '/v1' });
