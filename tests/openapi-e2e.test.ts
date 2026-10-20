import { CONTROL_PATH, NEVER_GUESSED, appServing, withApp, writeProject } from './helpers/dummyApp';

let mockPorts: number[] = [];

jest.mock('../src/config/ConfigManager', () => ({
  ConfigManager: { exists: async () => true, load: async () => ({ defaultPorts: mockPorts, model: 'none' }) },
}));
jest.mock('inquirer', () => ({ prompt: jest.fn() }));

import { Orchestrator } from '../src/core/Orchestrator';

const NON_INTERACTIVE = { yes: true, noAi: true, json: true } as const;

const SPEC = `openapi: 3.0.0
servers:
  - url: /api
paths:
  /ping:
    get:
      summary: ping
  /reports/summary:
    get:
      summary: summary
  /items/{id}:
    get:
      summary: needs an id the scan will not invent
  /items:
    post:
      summary: a write the scan never sends
`;

describe('a spec on disk is the only source of requests (no code routes, no adapter)', () => {
  beforeEach(() => {
    mockPorts = [];
  });

  it('requests only the concrete GET spec routes, never a path the spec did not declare', async () => {
    const dir = writeProject({ 'openapi.yaml': SPEC, 'main.go': 'package main\nfunc main() {}\n' });
    await withApp(appServing(['/api/ping', '/api/reports/summary', '/admin', '/.env', '/api/items/1']), async (app) => {
      mockPorts = [app.port];
      const r = await Orchestrator.analyze(dir, NON_INTERACTIVE);

      expect(r.graph.routes.map((x) => `${x.method} ${x.path}`).sort()).toEqual([
        'GET /api/items/{id}',
        'GET /api/ping',
        'GET /api/reports/summary',
        'POST /api/items',
      ]);
      expect(r.graph.routes.every((x) => x.source === 'openapi')).toBe(true);

      const spec = new Set(['/api/ping', '/api/reports/summary']);
      const paths = app.paths();
      expect(paths.filter((p) => !CONTROL_PATH.test(p)).every((p) => spec.has(p))).toBe(true);
      expect(paths).toContain('/api/ping');
      expect(paths).toContain('/api/reports/summary');
      expect(paths.filter((p) => CONTROL_PATH.test(p)).length).toBeLessThanOrEqual(1);
      for (const guessed of [...NEVER_GUESSED, '/api/items', '/api/items/1', '/api/items/{id}']) expect(paths).not.toContain(guessed);
      expect(app.requests.every((q) => q.method === 'GET')).toBe(true);

      expect(r.dynamic!.probed.map((p) => p.path).sort()).toEqual(['/api/ping', '/api/reports/summary']);
      expect(r.dynamic!.probed[0]!.why[0]).toBe('declared in OpenAPI/Swagger file openapi.yaml');
      expect(r.dynamic!.skipped.map((s) => `${s.method} ${s.path}`).sort()).toEqual(['GET /api/items/{id}', 'POST /api/items']);
    });
  });

  it('an unreadable (flow-style) spec means zero routes and zero requests', async () => {
    const dir = writeProject({ 'openapi.yaml': 'openapi: 3.0.0\npaths: {"/ping": {get: {}}}\n' });
    await withApp(appServing(['/ping', '/admin']), async (app) => {
      mockPorts = [app.port];
      const r = await Orchestrator.analyze(dir, NON_INTERACTIVE);
      expect(r.graph.routes).toEqual([]);
      expect(r.graph.discoveryNotes?.[0]).toMatch(/openapi\.yaml not used/);
      expect(app.requests).toEqual([]);
    });
  });
});
