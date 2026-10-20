/**
 * Regression guard: without the opt-in flag, a scan sends a request only to a
 * path that is discovered (code), declared (OpenAPI/Swagger on disk) or advertised
 * (linked by a page the scan already fetched). The dummy app below answers 200 on every
 * "classic" sensitive path, so any guess would be seen and would fail these tests.
 */
import { dummyJwt, CONTROL_PATH, expressProject, send, withApp, writeProject, type DummyApp, type Handler } from './helpers/dummyApp';

let mockPorts: number[] = [];

jest.mock('../src/config/ConfigManager', () => ({
  ConfigManager: { exists: async () => true, load: async () => ({ defaultPorts: mockPorts, model: 'none' }) },
}));
jest.mock('inquirer', () => ({ prompt: jest.fn() }));

import { Orchestrator, type AnalyzeOptions } from '../src/core/Orchestrator';

const NON_INTERACTIVE = { yes: true, noAi: true, json: true } as const;
const handlerLine = '(req, res) => res.send("ok")';

/** Present on the dummy app (HTTP 200) but never discovered, declared or advertised in these tests. */
const PRESENT_BUT_UNEVIDENCED = [
  '/.env',
  '/admin',
  '/api/admin',
  '/robots.txt',
  '/sitemap.xml',
  '/actuator',
  '/actuator/env',
  '/.git/config',
  '/debug',
  '/metrics',
  '/swagger.json',
  '/openapi.json',
  '/api/docs',
  '/health',
  '/login',
  '/server-status',
  '/phpinfo.php',
];

/** 200 on every path in `open`, 200 on the unevidenced paths too, 404 for the rest. */
function appWith(pages: Record<string, string> = {}): Handler {
  return (req, res) => {
    const p = (req.url ?? '/').split('?')[0] ?? '/';
    if (pages[p] !== undefined) return send(res, 200, pages[p]!);
    if (PRESENT_BUT_UNEVIDENCED.includes(p)) return send(res, 200, `<h1>Private ${p}</h1><p>records, users, billing</p>`);
    send(res, 404, 'not found', 'text/plain');
  };
}

function expectOnlyEvidencedPaths(app: DummyApp, evidenced: string[]): void {
  const requested = [...new Set(app.paths().filter((p) => !CONTROL_PATH.test(p)))];
  expect(requested.filter((p) => !evidenced.includes(p))).toEqual([]);
  for (const p of PRESENT_BUT_UNEVIDENCED) {
    if (!evidenced.includes(p)) expect(app.paths()).not.toContain(p);
  }
  expect(app.paths().filter((p) => CONTROL_PATH.test(p)).length).toBeLessThanOrEqual(1);
}

/** The scan modes that must all behave the same without the opt-in flag. */
const MODES: Array<[string, AnalyzeOptions]> = [
  ['default', {}],
  ['probeCommonPaths explicitly false', { probeCommonPaths: false }],
  ['aggressive', { aggressive: true }],
  ['active scan with a token', { active: true, token: dummyJwt({ sub: 'user-42' }) }],
];

interface Scenario {
  name: string;
  project: () => string;
  pages?: Record<string, string>;
  evidenced: string[];
  /** Extra paths the active scan may request: a declared `{id}` route filled from the supplied token's own claim. */
  activeOnly?: string[];
}

const SPEC = JSON.stringify({
  openapi: '3.0.0',
  servers: [{ url: '/api' }],
  paths: {
    '/status': { get: { summary: 'status' } },
    '/items/{id}': { get: { summary: 'needs an id the scan will not invent' } },
    '/items': { post: { summary: 'a write the scan never sends' } },
  },
  info: { title: 'fixture', description: 'Admin console lives at /admin, secrets at /.env, see /actuator and /robots.txt' },
});

const HOME = [
  '<!doctype html><html><body>',
  '<a href="/about">About</a>',
  '<a href="/logout">Log out</a>',
  '<p>Crawlers: see /robots.txt and /sitemap.xml. Admins: /admin. Debug: /actuator.</p>',
  '<form method="get" action="/admin"><input name="q"></form>',
  '</body></html>',
].join('');

const SCENARIOS: Scenario[] = [
  {
    name: 'an app with odd-named admin routes',
    project: () =>
      expressProject([`app.get("/ping", ${handlerLine});`, `app.get("/backoffice", ${handlerLine});`, `app.get("/staff/console", ${handlerLine});`]),
    pages: { '/ping': 'pong', '/backoffice': '<h1>back office</h1>', '/staff/console': '<h1>console</h1>' },
    evidenced: ['/ping', '/backoffice', '/staff/console'],
  },
  {
    name: 'an app with a .env file and actuator config on disk but no such routes',
    project: () =>
      expressProject([`app.get("/ping", ${handlerLine});`], {
        '.env': 'PLACEHOLDER_SETTING=dummy-value\n',
        'application.yml': 'management:\n  endpoints:\n    web:\n      exposure:\n        include: env,health\n',
        'README.md': 'Admin panel at /admin. Docs at /api/docs. Sitemap at /sitemap.xml.\n',
      }),
    pages: { '/ping': 'pong' },
    evidenced: ['/ping'],
  },
  {
    name: 'an OpenAPI file on disk and no code routes',
    project: () => writeProject({ 'openapi.json': SPEC, 'main.go': 'package main\nfunc main() {}\n' }),
    pages: { '/api/status': '{"ok":true}' },
    evidenced: ['/api/status'],
    activeOnly: ['/api/items/user-42'],
  },
  {
    name: 'a page that advertises one link and merely mentions the sensitive paths',
    project: () => expressProject([`app.get("/", ${handlerLine});`]),
    pages: { '/': HOME, '/about': '<h1>About</h1>' },
    evidenced: ['/', '/about'],
  },
  {
    name: 'a static project with no routes at all',
    project: () => writeProject({ 'index.html': HOME, 'css/site.css': 'body{margin:0}' }),
    evidenced: [],
  },
];

describe('without the opt-in flag, every request goes to a discovered, declared or advertised path', () => {
  beforeEach(() => {
    mockPorts = [];
  });

  for (const sc of SCENARIOS) {
    for (const [modeName, mode] of MODES) {
      it(`${sc.name} / ${modeName}`, async () => {
        const dir = sc.project();
        await withApp(appWith(sc.pages), async (app) => {
          mockPorts = [app.port];
          await Orchestrator.analyze(dir, { ...NON_INTERACTIVE, ...mode });

          expectOnlyEvidencedPaths(app, mode.active ? [...sc.evidenced, ...(sc.activeOnly ?? [])] : sc.evidenced);
          if (sc.evidenced.length === 0) expect(app.requests).toEqual([]);
          else for (const p of sc.evidenced) expect(app.paths()).toContain(p);
          for (const link of ['/logout']) expect(app.paths()).not.toContain(link);
        });
      });
    }
  }

  it('the exact never-requested list from the task, one app: /.env /admin /robots.txt /sitemap.xml /actuator', async () => {
    const dir = expressProject([`app.get("/ping", ${handlerLine});`, `app.get("/backoffice", ${handlerLine});`]);
    await withApp(appWith({ '/ping': 'pong', '/backoffice': '<h1>office</h1>' }), async (app) => {
      mockPorts = [app.port];
      await Orchestrator.analyze(dir, { ...NON_INTERACTIVE, aggressive: true });
      for (const p of ['/.env', '/admin', '/robots.txt', '/sitemap.xml', '/actuator']) expect(app.paths()).not.toContain(p);
      expectOnlyEvidencedPaths(app, ['/ping', '/backoffice']);
    });
  });

  it('only GET requests are sent to evidenced paths in the default scan', async () => {
    const dir = expressProject([`app.get("/ping", ${handlerLine});`, `app.post("/orders", ${handlerLine});`]);
    await withApp(appWith({ '/ping': 'pong', '/orders': 'o' }), async (app) => {
      mockPorts = [app.port];
      await Orchestrator.analyze(dir, NON_INTERACTIVE);
      expect(app.requests.every((r) => r.method === 'GET')).toBe(true);
      expect(app.paths()).not.toContain('/orders');
    });
  });
});
