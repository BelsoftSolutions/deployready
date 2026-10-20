const fastify = require('fastify')();

fastify.register(require('./routes/items'), { prefix: process.env.API_PREFIX });
