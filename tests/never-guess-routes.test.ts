import { CodeParser } from '../src/parser/CodeParser';
import { DynamicTester } from '../src/dynamic/DynamicTester';
import { setVerbose } from '../src/utils/logger';
import type { Finding, Route } from '../src/types';
import {
  CONTROL_PATH,
  NEVER_GUESSED,
  appServing,
  expressProject,
  isConcrete,
  send,
  withApp,
  writeProject,
  type DummyApp,
  type Handler,
} from './helpers/dummyApp';

const handlerLine = '(req, res) => res.send("ok")';
const isNote = (f: Finding) => (f as { note?: boolean }).note === true;
const byRule = (findings: Finding[], rule: string) => findings.filter((f) => f.rule === rule);

/** Every recorded request must be a discovered concrete path, bar the lazy catch-all control. */
function expectOnlyDiscoveredPaths(app: DummyApp, routes: Route[]): { control: string[] } {
  const discovered = new Set(routes.map((r) => r.path).filter(isConcrete));
  const paths = app.paths();
  const control = paths.filter((p) => CONTROL_PATH.test(p));
  const others = paths.filter((p) => !CONTROL_PATH.test(p));
  expect(others.filter((p) => !discovered.has(p))).toEqual([]);
  for (const p of NEVER_GUESSED) {
    if (!discovered.has(p)) expect(paths).not.toContain(p);
  }
  return { control };
}

function expectNothingGuessedByName(app: DummyApp): void {
  const paths = app.paths();
  for (const guessed of NEVER_GUESSED) expect(paths).not.toContain(guessed);
}

describe('an app whose admin area has an odd name', () => {
  const ODD_NAMES = ['/backoffice', '/staff/console', '/Internal/ops'];

  it('is found by the real parser, requested only where discovered, and reported open', async () => {
    const dir = expressProject([
      `app.get("/ping", ${handlerLine});`,
      ...ODD_NAMES.map((n) => `app.get("${n}", ${handlerLine});`),
    ]);
    const graph = await CodeParser.analyze(dir);
    expect(graph.routes.map((r) => r.path).sort()).toEqual(['/Internal/ops', '/backoffice', '/ping', '/staff/console']);

    await withApp(appServing([...ODD_NAMES, '/ping']), async (app) => {
      const r = await DynamicTester.run(app.baseUrl, graph.routes, { aggressive: true });

      const { control } = expectOnlyDiscoveredPaths(app, graph.routes);
      expectNothingGuessedByName(app);
      expect(control.length).toBeLessThanOrEqual(1);
      expect(app.paths().filter((p) => ODD_NAMES.includes(p)).length).toBeGreaterThan(0);

      const exposed = byRule(r.findings, 'exposed-admin-route').map((f) => f.endpoint).sort();
      expect(exposed).toEqual(['/Internal/ops', '/backoffice', '/staff/console']);
    });
  });

  it('sends no catch-all control request when nothing is open', async () => {
    const dir = expressProject(ODD_NAMES.map((n) => `app.get("${n}", ${handlerLine});`));
    const graph = await CodeParser.analyze(dir);
    await withApp(
      appServing([], (res) => send(res, 401, '{"error":"unauthorized"}', 'application/json')),
      async (app) => {
        const r = await DynamicTester.run(app.baseUrl, graph.routes, { aggressive: true });
        const { control } = expectOnlyDiscoveredPaths(app, graph.routes);
        expect(control).toEqual([]);
        expectNothingGuessedByName(app);
        expect(byRule(r.findings, 'exposed-admin-route')).toEqual([]);
      },
    );
  });

  it('sends nothing at all when the odd-named routes are not in the route list', async () => {
    await withApp(appServing(ODD_NAMES), async (app) => {
      await DynamicTester.run(app.baseUrl, [], { aggressive: true });
      expect(app.requests).toEqual([]);
    });
  });
});

describe('odd-named admin routes get exactly the treatment /admin gets', () => {
  const NAMES = ['/admin', '/backoffice', '/staff/console', '/Internal/ops'];
  const spa = '<!doctype html><html><body><div id="root"></div><script src="/bundle.js"></script></body></html>';
  const notFound = (res: Parameters<Handler>[1]) => send(res, 404, 'nf', 'text/plain');

  const scenarios: Array<{ name: string; handler: (n: string) => Handler; reported: boolean; control: 'none' | 'one' }> = [
    { name: 'open (200)', handler: (n) => appServing([n]), reported: true, control: 'one' },
    {
      name: 'protected (401)',
      handler: (n) => appServing([], (res, p) => (p === n ? send(res, 401, '{"error":"unauthorized"}', 'application/json') : notFound(res))),
      reported: false,
      control: 'none',
    },
    {
      name: 'protected (403)',
      handler: (n) => appServing([], (res, p) => (p === n ? send(res, 403, '{"error":"forbidden"}', 'application/json') : notFound(res))),
      reported: false,
      control: 'none',
    },
    {
      name: 'protected (302 to /login)',
      handler: (n) => (req, res) => {
        const p = (req.url ?? '/').split('?')[0];
        if (p === n) return send(res, 302, '', 'text/plain', { location: '/login' });
        if (p === '/login') return send(res, 200, '<form method="post"></form>');
        notFound(res);
      },
      reported: false,
      control: 'none',
    },
    { name: 'catch-all single-page app', handler: () => (_req, res) => send(res, 200, spa), reported: false, control: 'one' },
  ];

  for (const name of NAMES) {
    for (const sc of scenarios) {
      it(`${name}: ${sc.name} -> ${sc.reported ? 'reports exposed-admin-route' : 'reports nothing'}`, async () => {
        const dir = expressProject([`app.get("${name}", ${handlerLine});`, `app.get("/ping", ${handlerLine});`]);
        const graph = await CodeParser.analyze(dir);
        expect(graph.routes.map((r) => r.path)).toContain(name);

        await withApp(sc.handler(name), async (app) => {
          const r = await DynamicTester.run(app.baseUrl, graph.routes, { aggressive: true });
          const { control } = expectOnlyDiscoveredPaths(app, graph.routes);
          expect(app.paths()).not.toContain('/login');
          expect(control).toHaveLength(sc.control === 'one' ? 1 : 0);

          const exposed = byRule(r.findings, 'exposed-admin-route');
          if (sc.reported) {
            expect(exposed.map((f) => f.endpoint)).toEqual([name]);
            expect(exposed[0]!.severity).toBe('critical');
          } else {
            expect(exposed).toEqual([]);
            expect(byRule(r.findings, 'auth-bypass')).toEqual([]);
          }
        });
      });
    }
  }
});

describe('admin evidence from guard middleware on a neutral path', () => {
  it('classifies requireRole("staff") and isStaff routes as admin-like through the real parser', async () => {
    const dir = expressProject([
      `app.get("/reports/summary", requireRole("staff"), ${handlerLine});`,
      `app.get("/team/area", isStaff, ${handlerLine});`,
      `app.get("/open/info", ${handlerLine});`,
    ]);
    const graph = await CodeParser.analyze(dir);
    const guarded = Object.fromEntries(graph.routes.map((r) => [r.path, r.guarded]));
    expect(guarded).toEqual({ '/reports/summary': true, '/team/area': true, '/open/info': false });

    await withApp(appServing(['/reports/summary', '/team/area', '/open/info']), async (app) => {
      const r = await DynamicTester.run(app.baseUrl, graph.routes);
      expectOnlyDiscoveredPaths(app, graph.routes);
      expect(byRule(r.findings, 'exposed-admin-route').map((f) => f.endpoint).sort()).toEqual(['/reports/summary', '/team/area']);
      expect(byRule(r.findings, 'auth-bypass').map((f) => f.endpoint).sort()).toEqual(['/reports/summary', '/team/area']);
    });
  });

  it('a neutral, unguarded route that answers 200 is not reported as an admin route', async () => {
    const dir = expressProject([`app.get("/open/info", ${handlerLine});`]);
    const graph = await CodeParser.analyze(dir);
    await withApp(appServing(['/open/info']), async (app) => {
      const r = await DynamicTester.run(app.baseUrl, graph.routes);
      expect(byRule(r.findings, 'exposed-admin-route')).toEqual([]);
      expect(app.paths().filter((p) => CONTROL_PATH.test(p))).toEqual([]);
    });
  });
});

describe('routes that need a path parameter', () => {
  it('the dynamic scan never requests /users/:id, with or without an invented id', async () => {
    const dir = expressProject([`app.get("/ping", ${handlerLine});`, `app.get("/users/:id", ${handlerLine});`]);
    const graph = await CodeParser.analyze(dir);
    expect(graph.routes.map((r) => r.path)).toContain('/users/:id');

    await withApp(appServing(['/ping', '/users/1', '/users/123', '/users/me']), async (app) => {
      const r = await DynamicTester.run(app.baseUrl, graph.routes, { aggressive: true });
      expectOnlyDiscoveredPaths(app, graph.routes);
      expect(app.paths().filter((p) => p.startsWith('/users'))).toEqual([]);
      expect(app.paths()).toContain('/ping');
      const notes = r.findings.filter(isNote);
      expect(notes.length).toBeGreaterThan(0);
      expect(notes.map((f) => f.description).join(' ')).toContain('/users/:id');
    });
  });
});

describe('no routes discovered', () => {
  it('DynamicTester.run with an empty route list sends zero HTTP requests and says so in a non-scored note', async () => {
    await withApp(appServing(['/admin', '/', '/health']), async (app) => {
      const r = await DynamicTester.run(app.baseUrl, [], { aggressive: true });
      expect(app.requests).toEqual([]);
      const notes = r.findings.filter(isNote);
      expect(notes.map((n) => n.title)).toContain('No routes discovered; dynamic checks skipped');
      expect(r.findings.filter((f) => !isNote(f))).toEqual([]);
      for (const n of notes) expect(n.severity).toBe('info');
    });
  });

  it('a real unsupported-stack project (plain static folder) yields no routes and zero requests', async () => {
    const dir = writeProject({ 'index.html': '<h1>hello</h1>', 'css/site.css': 'body{margin:0}', 'js/app.js': 'console.log("hi")' });
    const graph = await CodeParser.analyze(dir);
    expect(graph.routes).toEqual([]);
    await withApp(appServing(['/admin', '/']), async (app) => {
      const r = await DynamicTester.run(app.baseUrl, graph.routes, { aggressive: true });
      expect(app.requests).toEqual([]);
      expect(r.findings.map((f) => f.title)).toContain('No routes discovered; dynamic checks skipped');
    });
  });
});

describe('verbose output explains every decision', () => {
  let spy: jest.SpyInstance;
  beforeEach(() => {
    spy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => {
    setVerbose(false);
    spy.mockRestore();
  });
  const lines = () => spy.mock.calls.map((c) => c.join(' '));

  it('lists each probed route with its reason and each skipped route with its reason', async () => {
    const dir = expressProject([
      `app.get("/backoffice", ${handlerLine});`,
      `app.get("/ping", ${handlerLine});`,
      `app.get("/users/:id", ${handlerLine});`,
      `app.post("/orders", ${handlerLine});`,
    ]);
    const graph = await CodeParser.analyze(dir);
    setVerbose(true);
    await withApp(appServing(['/backoffice', '/ping']), async (app) => {
      await DynamicTester.run(app.baseUrl, graph.routes);
    });
    const out = lines();
    const forPath = (p: string) => out.filter((l) => l.includes(p));

    const backoffice = forPath(' /backoffice').filter((l) => /^\[debug\] \[probe\] GET /.test(l));
    expect(backoffice).toHaveLength(1);
    expect(backoffice[0]).toMatch(/discovered at server\.js/);

    const ping = forPath(' /ping').filter((l) => /^\[debug\] \[probe\] GET /.test(l));
    expect(ping).toHaveLength(1);
    expect(ping[0]).toMatch(/discovered at server\.js/);

    const users = forPath('/users/:id').filter((l) => /^\[debug\] \[skip\] /.test(l));
    expect(users).toHaveLength(1);
    expect(users[0]).toMatch(/path parameter/);

    const orders = forPath('/orders').filter((l) => /^\[debug\] \[skip\] /.test(l));
    expect(orders).toHaveLength(1);
    expect(orders[0]).toMatch(/non-GET/);
  });

  it('logs nothing about routes when verbose is off', async () => {
    const dir = expressProject([`app.get("/ping", ${handlerLine});`]);
    const graph = await CodeParser.analyze(dir);
    await withApp(appServing(['/ping']), async (app) => {
      await DynamicTester.run(app.baseUrl, graph.routes);
    });
    expect(lines().filter((l) => l.includes('/ping'))).toEqual([]);
  });
});
