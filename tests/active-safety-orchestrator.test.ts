/**
 * Safety levels and --dry-run wired through Orchestrator.analyze, against a real
 * loopback app: what is (and is not) sent at each level.
 */
import { appServing, dummyJwt, expressProject, send, withApp } from './helpers/dummyApp';

let mockPorts: number[] = [];
let mockActive: Record<string, unknown> = {};
jest.mock('../src/config/ConfigManager', () => ({
  ConfigManager: { exists: async () => true, load: async () => ({ defaultPorts: mockPorts, model: 'none', active: mockActive }) },
}));
jest.mock('inquirer', () => ({ prompt: jest.fn() }));

import { Orchestrator } from '../src/core/Orchestrator';

const h = '(req, res) => res.send("ok")';
const project = () =>
  expressProject([
    `app.get("/users/:id", ${h});`,
    `app.get("/logout", ${h});`,
    `app.delete("/users/:id", ${h});`,
  ]);
const app = appServing(['/logout'], (res, p) =>
  p.startsWith('/users/') ? send(res, 401, '{"error":"unauthorized"}', 'application/json') : send(res, 404, 'nf', 'text/plain'),
);
const run = (over: Record<string, unknown>) =>
  Orchestrator.analyze(project(), { yes: true, noAi: true, json: true, noDynamic: true, active: true, token: dummyJwt({ sub: 'u1' }), tokenB: dummyJwt({ sub: 'u2' }), ...over });

beforeEach(() => {
  mockActive = {};
});

describe('Orchestrator: active safety levels', () => {
  it('--dry-run sends nothing at all', async () => {
    await withApp(app, async (a) => {
      mockPorts = [a.port];
      await run({ dryRun: true, activeUrl: a.baseUrl });
      expect(a.requests).toEqual([]);
    });
  });

  it('passive sends nothing at all', async () => {
    await withApp(app, async (a) => {
      mockPorts = [a.port];
      await run({ safetyLevel: 'passive' });
      expect(a.requests).toEqual([]);
    });
  });

  it('read-only (default): GET only, never the side-effect route, no write probe', async () => {
    await withApp(app, async (a) => {
      mockPorts = [a.port];
      await run({});
      expect(a.requests.length).toBeGreaterThan(0);
      expect(a.requests.every((r) => r.method === 'GET')).toBe(true);
      expect(a.paths()).not.toContain('/logout');
    });
  });

  it('controlled-active adds the unauthenticated DELETE probe (non-existent id)', async () => {
    await withApp(app, async (a) => {
      mockPorts = [a.port];
      await run({ safetyLevel: 'controlled-active' });
      const del = a.requests.filter((r) => r.method === 'DELETE');
      expect(del).toHaveLength(1);
      expect(del[0]!.path).toMatch(/^\/users\/__deployready_probe_/);
    });
  });

  it('stateful is refused (nothing sent) unless the config declares a disposable environment', async () => {
    await withApp(app, async (a) => {
      mockPorts = [a.port];
      await run({ safetyLevel: 'stateful' });
      expect(a.requests).toEqual([]);
      mockActive = { disposableEnvironment: true };
      await run({ safetyLevel: 'stateful' });
      expect(a.paths()).toContain('/logout');
    });
  });

  it('honours the config request budget', async () => {
    await withApp(app, async (a) => {
      mockPorts = [a.port];
      mockActive = { maxRequests: 1, safetyLevel: 'controlled-active' };
      await run({});
      expect(a.requests).toHaveLength(1);
    });
  });
});
