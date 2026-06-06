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
});

describe('CodeParser.analyze', () => {
  it('detects the express stack and routes from the sample app', async () => {
    const graph = await CodeParser.analyze(SAMPLE);
    expect(graph.stack.stack).toBe('express');
    expect(graph.fileCount).toBeGreaterThan(0);
    const paths = graph.routes.map((r) => r.path);
    expect(paths).toContain('/login');
    expect(graph.entryPoints.some((e) => e.includes('server.js'))).toBe(true);
  });
});
