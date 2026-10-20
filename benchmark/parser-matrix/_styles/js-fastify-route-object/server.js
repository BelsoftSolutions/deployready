const fastify = require('fastify')();

fastify.route({
  method: 'GET',
  url: '/ping',
  handler: async () => ({ pong: true }),
});
