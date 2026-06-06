import * as path from 'path';
import { CodeParser } from '../src/parser/CodeParser';
import { BabelAdapter } from '../src/parser/adapters/BabelAdapter';

const SAMPLE = path.join(__dirname, 'sample-app');

describe('BabelAdapter', () => {
  const adapter = new BabelAdapter();

  it('extracts requires and routes', () => {
    const src = `
      const express = require('express');
      const router = express.Router();
      router.post('/login', async (req, res) => {});
      router.get('/profile', auth, handler);
      module.exports = router;
    `;
    const r = adapter.parse('routes/auth.js', src);
    expect(r.imports).toContain('express');
    const login = r.routes.find((x) => x.path === '/login');
    const profile = r.routes.find((x) => x.path === '/profile');
    expect(login?.method).toBe('POST');
    expect(login?.guarded).toBe(false);
    expect(profile?.guarded).toBe(true); // 3 args => middleware present
  });

  it('never throws on broken source', () => {
    expect(() => adapter.parse('x.js', 'const = = =;;; function (')).not.toThrow();
  });

  it('captures sub-router mounts and resolves the source module', () => {
    const src = `
      const authRoutes = require('./routes/auth');
      const userRoutes = require('./routes/user');
      app.use('/api/auth', authRoutes);
      app.use('/api', userRoutes);
      app.use(express.json());        // middleware, not a mount
    `;
    const r = adapter.parse('server.js', src);
    expect(r.mounts).toEqual(
      expect.arrayContaining([
        { prefix: '/api/auth', source: './routes/auth' },
        { prefix: '/api', source: './routes/user' },
      ]),
    );
    // `use` is no longer mis-recorded as a route.
    expect(r.routes).toHaveLength(0);
  });
});

describe('CodeParser.analyze', () => {
  it('detects the express stack and routes from the sample app', async () => {
    const graph = await CodeParser.analyze(SAMPLE);
    expect(graph.stack.stack).toBe('express');
    expect(graph.fileCount).toBeGreaterThan(0);
    const paths = graph.routes.map((r) => r.path);
    // Mount prefixes are composed across files: routes/auth.js is mounted at /api/auth.
    expect(paths).toContain('/api/auth/login');
    expect(paths).toContain('/api/auth/profile');
    expect(paths).not.toContain('/login'); // the bare router-local path must not leak
    expect(graph.entryPoints.some((e) => e.includes('server.js'))).toBe(true);
  });

  it('marks the mounted guarded route and composes its full path', async () => {
    const graph = await CodeParser.analyze(SAMPLE);
    const profile = graph.routes.find((r) => r.path === '/api/auth/profile');
    expect(profile?.guarded).toBe(true);
  });
});
