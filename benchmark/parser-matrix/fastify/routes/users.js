module.exports = async function usersRoutes(fastify) {
  fastify.get('/', async () => []);
  fastify.get('/:id', async (request) => ({ id: request.params.id }));
  fastify.post('/', { preHandler: [fastify.authenticate] }, async (request, reply) => {
    reply.code(201).send(request.body);
  });
};
