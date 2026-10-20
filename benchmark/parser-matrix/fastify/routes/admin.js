module.exports = async function adminRoutes(fastify) {
  fastify.addHook('onRequest', fastify.authenticate);

  fastify.get('/stats', async () => ({ users: 0 }));

  fastify.route({
    method: 'DELETE',
    url: '/users/:id',
    handler: async (request, reply) => reply.code(204).send(),
  });
};
