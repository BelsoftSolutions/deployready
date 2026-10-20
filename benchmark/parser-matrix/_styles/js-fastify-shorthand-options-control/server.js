const fastify = require('fastify')();

fastify.get('/ping', { schema: { response: { 200: { type: 'object' } } } }, async () => ({ pong: true }));
