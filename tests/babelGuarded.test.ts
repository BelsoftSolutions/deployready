import * as path from 'path';
import { CodeParser } from '../src/parser/CodeParser';
import { BabelAdapter } from '../src/parser/adapters/BabelAdapter';

const adapter = new BabelAdapter();

function guards(src: string): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const r of adapter.parse('x.js', src).routes) out[`${r.method} ${r.path}`] = r.guarded;
  return out;
}

describe('route-level guard recognition', () => {
  it('marks recognised auth middleware as guarded', () => {
    const g = guards(`
      app.get('/a', requireAuth, handler);
      app.get('/b', passport.authenticate('jwt'), h);
      app.get('/c', validate, authorize('admin'), h);
      app.get('/d', expressjwt({ secret: s }), h);
      app.get('/e', [validate, auth.required], h);
    `);
    expect(g).toEqual({
      'GET /a': true,
      'GET /b': true,
      'GET /c': true,
      'GET /d': true,
      'GET /e': true,
    });
  });

  it('does not treat arbitrary 3+ argument routes as guarded', () => {
    const g = guards(`
      app.post('/b', validate, handler);
      app.get('/c', handler, extra);
      app.post('/up', upload.single('f'), h);
      app.get('/d', rateLimiter, h);
      app.get('/e', cors(), express.json(), logger, asyncHandler(h2), cache('5 min'), h);
      app.get('/f', handler, requireAuth);
      app.get('/g', requireAuth);
      app.get('/h', authorName, h);
      app.get('/i', oauthCallback, h);
      app.get('/j', ...mws, h);
    `);
    for (const [k, v] of Object.entries(g)) expect([k, v]).toEqual([k, false]);
    expect(Object.keys(g)).toHaveLength(10);
  });

  it('never treats the last argument (the handler) as the guard', () => {
    expect(guards(`app.get('/x', requireAuth);`)['GET /x']).toBe(false);
  });
});

describe('use() scope tracking', () => {
  it('router.use(auth) guards later routes on the same object only', () => {
    const g = guards(`
      router.get('/before', h);
      router.use(authenticate);
      router.get('/x', h);
      router.post('/y', validate, h);
      other.get('/z', h);
    `);
    expect(g).toEqual({
      'GET /before': false,
      'GET /x': true,
      'POST /y': true,
      'GET /z': false,
    });
  });

  it('use(mw1, mw2) with any auth middleware guards later routes', () => {
    const g = guards(`
      app.use(cors(), requireAuth, extra);
      app.get('/x', h);
    `);
    expect(g['GET /x']).toBe(true);
  });

  it('a non-auth app.use(mw) guards nothing', () => {
    const g = guards(`
      app.use(express.json());
      app.use(cors());
      app.use(rateLimiter);
      app.get('/x', h);
    `);
    expect(g['GET /x']).toBe(false);
  });

  it("use('/prefix', auth) guards only later routes under that segment prefix", () => {
    const g = guards(`
      app.get('/admin/early', h);
      app.use('/admin', requireAuth);
      app.get('/admin/stats', h);
      app.get('/admin', h);
      app.get('/public', h);
      app.get('/administrator', h);
    `);
    expect(g).toEqual({
      'GET /admin/early': false,
      'GET /admin/stats': true,
      'GET /admin': true,
      'GET /public': false,
      'GET /administrator': false,
    });
  });

  it('is conservative with dynamic or ambiguous prefixes and spreads', () => {
    const g = guards(`
      app.use(PREFIX, requireAuth);
      app.use(logger, requireAuth);
      app.use(\`/\${v}/x\`, requireAuth);
      app.use('/api/*', requireAuth);
      app.use(...mws);
      app.get('/api/a', h);
      app.get('/x', h);
    `);
    expect(g['GET /api/a']).toBe(false);
    expect(g['GET /x']).toBe(false);
  });

  it('does not record recognised middleware as a router mount, but keeps real mounts', () => {
    const r = adapter.parse(
      'server.js',
      `
      const requireAuth = require('./middleware/auth');
      const authRoutes = require('./routes/auth');
      const auth = require('./routes/authRouter');
      app.use('/secure', requireAuth);
      app.use('/api/auth', authRoutes);
      app.use('/legacy', auth);
    `,
    );
    expect(r.mounts).toEqual(
      expect.arrayContaining([
        { prefix: '/api/auth', source: './routes/auth' },
        { prefix: '/legacy', source: './routes/authRouter' },
      ]),
    );
    expect(r.mounts.find((m) => m.source === './middleware/auth')).toBeUndefined();
  });

  it('a router-module binding named like a guard is a mount, not a guard', () => {
    const g = guards(`
      const auth = require('./routes/auth');
      app.use('/auth', auth);
      app.get('/auth/me', h);
    `);
    expect(g['GET /auth/me']).toBe(false);
  });

  it('never throws on odd syntax', () => {
    expect(() => adapter.parse('x.js', `app.use(; app.get('/x', ...); router.use(()=>)`)).not.toThrow();
  });
});

describe('mount guard propagation (CodeParser.analyze)', () => {
  const FIXTURE = path.join(__dirname, 'guarded-app');

  it('guards routes of a router mounted behind auth middleware, composing the prefix', async () => {
    const graph = await CodeParser.analyze(FIXTURE);
    const byPath = Object.fromEntries(graph.routes.map((r) => [`${r.method} ${r.path}`, r.guarded]));
    expect(byPath['GET /api/users']).toBe(true);
    expect(byPath['GET /api/users/:id']).toBe(true);
  });

  it('leaves a plain mount unguarded and still mounted', async () => {
    const graph = await CodeParser.analyze(FIXTURE);
    const login = graph.routes.find((r) => r.path === '/api/auth/login');
    expect(login?.guarded).toBe(false);
    expect(graph.routes.find((r) => r.path === '/login')).toBeUndefined();
    const health = graph.routes.find((r) => r.path === '/health');
    expect(health?.guarded).toBe(false);
  });

  it('guards per mount point when the same router is mounted guarded and unguarded', async () => {
    const graph = await CodeParser.analyze(FIXTURE);
    const byPath = Object.fromEntries(graph.routes.map((r) => [r.path, r.guarded]));
    expect(byPath['/guarded/ping']).toBe(true);
    expect(byPath['/open/ping']).toBe(false);
  });

  it('propagates a guarded mount to routers mounted inside the mounted router', async () => {
    const graph = await CodeParser.analyze(FIXTURE);
    const byPath = Object.fromEntries(graph.routes.map((r) => [r.path, r.guarded]));
    expect(byPath['/admin/stats']).toBe(true);
    expect(byPath['/admin/inner/deep']).toBe(true);
  });

  it('does not mount the middleware file as a router', () => {
    const r = adapter.parse(
      'server.js',
      `const authMw = require('./middleware/auth');
       const usersRouter = require('./routes/users');
       app.use('/api/users', authMw, usersRouter);`,
    );
    expect(r.mounts).toEqual([{ prefix: '/api/users', source: './routes/users', guarded: true, guardNames: ['authMw'] }]);
  });

  it('a mount after an earlier use() covering its prefix is guarded; one before is not', () => {
    const r = adapter.parse(
      'server.js',
      `const a = require('./routes/a');
       const b = require('./routes/b');
       const c = require('./routes/c');
       app.use('/x', b);
       app.use('/api', requireAuth);
       app.use('/api/a', a);
       app.use('/other', c);
       app.use('/x', b);`,
    );
    const find = (src: string) => r.mounts.filter((m) => m.source === src).map((m) => m.guarded === true);
    expect(find('./routes/a')).toEqual([true]);
    expect(find('./routes/c')).toEqual([false]);
    expect(find('./routes/b')).toEqual([false, false]);
  });

  it('a router listed before the auth middleware in one use() call is not guarded', () => {
    const r = adapter.parse(
      'server.js',
      `const u = require('./routes/u');
       app.use('/u', u, requireAuth);`,
    );
    expect(r.mounts).toEqual([{ prefix: '/u', source: './routes/u' }]);
  });
});
