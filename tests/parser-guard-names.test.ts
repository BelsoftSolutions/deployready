import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CodeParser } from '../src/parser/CodeParser';
import { BabelAdapter } from '../src/parser/adapters/BabelAdapter';
import { PythonAdapter } from '../src/parser/adapters/PythonAdapter';
import { EndpointMapper } from '../src/dynamic/EndpointMapper';
import type { Route } from '../src/types';

const babel = new BabelAdapter();
const python = new PythonAdapter();

describe('BabelAdapter guardNames', () => {
  it('records route-level guard names, callee name plus string arguments, and auth member objects', () => {
    const { routes } = babel.parse(
      'x.js',
      `
      app.get('/a', requireAdmin, h);
      app.get('/b', requireRole('staff'), h);
      app.get('/c', auth.required, h);
      app.get('/d', [validate, requireRole(['staff', 'ops'])], h);
      app.get('/e', passport.authenticate('jwt'), h);
      app.get('/f', validate, cors(), h);
      app.get('/g', h);
    `,
    );
    const names = Object.fromEntries(routes.map((r) => [r.path, r.guardNames]));
    expect(names['/a']).toEqual(['requireAdmin']);
    expect(names['/b']).toEqual(['requireRole', 'staff']);
    expect(names['/c']).toEqual(['required', 'auth']);
    expect(names['/d']).toEqual(['requireRole', 'staff', 'ops']);
    expect(names['/e']).toEqual(['authenticate', 'passport', 'jwt']);
    expect(names['/f']).toBeUndefined();
    expect(names['/g']).toBeUndefined();
  });

  it('omits guardNames on unguarded routes, and never records the handler', () => {
    const { routes } = babel.parse(
      'x.js',
      `app.get('/p', validate, h); app.get('/q', handler, requireAuth); app.get('/r', requireAuth);`,
    );
    expect(routes).toHaveLength(3);
    for (const r of routes) {
      expect(r.guarded).toBe(false);
      expect('guardNames' in r).toBe(false);
    }
  });

  it('records use()-scoped guards only for routes the scope covers', () => {
    const { routes } = babel.parse(
      'x.js',
      `
      app.get('/before', h);
      app.use('/backoffice', isStaff);
      app.get('/backoffice/x', h);
      app.get('/public', h);
    `,
    );
    const by = Object.fromEntries(routes.map((r) => [r.path, r]));
    expect(by['/backoffice/x']).toMatchObject({ guarded: true, guardNames: ['isStaff'] });
    expect('guardNames' in by['/before']!).toBe(false);
    expect('guardNames' in by['/public']!).toBe(false);
  });

  it('stores mount guards on the MountHit', () => {
    const { mounts } = babel.parse(
      'x.js',
      `
      import reports from './reports';
      import open from './open';
      app.use('/api/reports', requireRole('staff'), reports);
      app.use('/open', open);
    `,
    );
    expect(mounts.find((m) => m.prefix === '/api/reports')).toMatchObject({
      guarded: true,
      guardNames: ['requireRole', 'staff'],
    });
    expect('guardNames' in mounts.find((m) => m.prefix === '/open')!).toBe(false);
  });

  it('marks requireStaff / isStaff routes as guarded', () => {
    const { routes } = babel.parse(
      'x.js',
      `app.get('/a', requireStaff, h); app.get('/b', isStaff, h); app.get('/c', staffList, h);`,
    );
    expect(routes.map((r) => r.guarded)).toEqual([true, true, false]);
  });
});

describe('CodeParser guardNames over mounts', () => {
  let dir: string;
  const write = (rel: string, body: string) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  };
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardnames-'));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  async function routesOf(): Promise<Route[]> {
    return (await CodeParser.analyze(dir)).routes;
  }

  it('accumulates guard names across a two-level mount chain, with the route own guard last', async () => {
    write('app.js', `const api = require('./api');\napp.use('/api', requireAuth, api);\n`);
    write(
      'api.js',
      `const router = require('express').Router();\nconst reports = require('./reports');\nrouter.use('/reports', requireRole('staff'), reports);\nrouter.get('/products', (q, s) => s.json([]));\nmodule.exports = router;\n`,
    );
    write(
      'reports.js',
      `const router = require('express').Router();\nrouter.get('/', (q, s) => s.json([]));\nrouter.get('/export', requireAdmin, (q, s) => s.json([]));\nmodule.exports = router;\n`,
    );
    const by = Object.fromEntries((await routesOf()).map((r) => [r.path, r]));
    expect(by['/api/reports']).toMatchObject({ guarded: true, guardNames: ['requireAuth', 'requireRole', 'staff'] });
    expect(by['/api/reports/export']).toMatchObject({
      guarded: true,
      guardNames: ['requireAuth', 'requireRole', 'staff', 'requireAdmin'],
    });
    expect(by['/api/products']).toMatchObject({ guarded: true, guardNames: ['requireAuth'] });
  });

  it('leaves guardNames off unguarded routes', async () => {
    write('app.js', `const api = require('./api');\napp.use('/api', api);\napp.get('/ping', (q, s) => s.send('ok'));\n`);
    write(
      'api.js',
      `const router = require('express').Router();\nrouter.get('/products', (q, s) => s.json([]));\nmodule.exports = router;\n`,
    );
    const routes = await routesOf();
    expect(routes).toHaveLength(2);
    for (const r of routes) {
      expect(r.guarded).toBe(false);
      expect('guardNames' in r).toBe(false);
    }
  });

  it('feeds admin evidence: a staff-guarded mounted router is sensitive, a plain route is not', async () => {
    write(
      'app.js',
      `const reports = require('./reports');\nconst products = require('./products');\napp.use('/api/reports', requireRole('staff'), reports);\napp.use('/api/products', products);\n`,
    );
    const routerFile = `const router = require('express').Router();\nrouter.get('/', (q, s) => s.json([]));\nmodule.exports = router;\n`;
    write('reports.js', routerFile);
    write('products.js', routerFile);
    const { targets } = EndpointMapper.plan(await routesOf());
    const reports = targets.find((t) => t.path === '/api/reports')!;
    const products = targets.find((t) => t.path === '/api/products')!;
    expect(reports.sensitive).toBe(true);
    expect(reports.why.join('\n')).toContain('middleware "staff"');
    expect(products.sensitive).toBe(false);
  });
});

describe('PythonAdapter guardNames', () => {
  it('records identifiers inside Depends(...) on the route line', () => {
    const { routes } = python.parse(
      'main.py',
      [
        '@app.get("/users", dependencies=[Depends(get_admin_user)])',
        'def a(): pass',
        '@app.get("/me", dependencies=[Depends(security.get_current_user)])',
        'def b(): pass',
        '@app.get("/open")',
        'def c(): pass',
        '@router.get("/staff", dependencies=[Depends(require_role("staff"), use_cache=False)])',
        'def d(): pass',
      ].join('\n'),
    );
    const by = Object.fromEntries(routes.map((r) => [r.path, r]));
    expect(by['/users']!.guardNames).toEqual(['get_admin_user']);
    expect(by['/users']!.guarded).toBe(true);
    expect(by['/me']!.guardNames).toEqual(['get_current_user']);
    expect(by['/staff']!.guardNames).toEqual(['require_role', 'staff']);
    expect('guardNames' in by['/open']!).toBe(false);
    expect(by['/open']!.guarded).toBe(false);
  });
});
