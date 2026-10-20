module.exports = async function v1Routes(fastify) {
  fastify.register(require('./items'), { prefix: '/items' });
};
