const fastify = require('fastify')({ logger: true });

fastify.register(require('@fastify/jwt'), { secret: process.env.JWT_SECRET });
fastify.decorate('authenticate', async (request, reply) => {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.send(err);
  }
});

fastify.get('/health', async () => ({ status: 'ok' }));
fastify.register(require('./routes/users'), { prefix: '/api/users' });
fastify.register(require('./routes/admin'), { prefix: '/admin' });

fastify.listen({ port: 3000 });
