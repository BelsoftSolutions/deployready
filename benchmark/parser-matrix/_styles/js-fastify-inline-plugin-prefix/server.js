const fastify = require('fastify')();

fastify.register(async function itemsPlugin(app) {
  app.get('/items', async () => []);
}, { prefix: '/api' });
