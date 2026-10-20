import { shouldFail, toCiJson } from '../src/core/CiGate';
import { ScoreCalculator } from '../src/analysis/ScoreCalculator';
import type { ScanReport } from '../src/types';
import { setVerbose } from '../src/utils/logger';
import { CONTROL_PATH, NEVER_GUESSED, appServing, dummyJwt, expressProject, send, withApp, writeProject } from './helpers/dummyApp';

let mockPorts: number[] = [];
const mockPrompt = jest.fn();

jest.mock('../src/config/ConfigManager', () => ({
  ConfigManager: { exists: async () => true, load: async () => ({ defaultPorts: mockPorts, model: 'none' }) },
}));
jest.mock('inquirer', () => ({ prompt: (...a: unknown[]) => mockPrompt(...a) }));

import { Orchestrator } from '../src/core/Orchestrator';

const handlerLine = '(req, res) => res.send("ok")';
const NON_INTERACTIVE = { yes: true, noAi: true, json: true } as const;
const NO_ROUTES_NOTE = 'No routes discovered; dynamic checks skipped';

const noteOf = (r: ScanReport, title: string) =>
  r.findings.find((f) => f.title === title && (f as { note?: boolean }).note === true);
const notesCount = (r: ScanReport) => (r.summary as { notes?: number }).notes ?? 0;

beforeEach(() => {
  mockPrompt.mockReset();
  mockPorts = [];
});
afterEach(() => setVerbose(false));

const NO_ROUTE_PROJECTS: Array<[string, () => string]> = [
  ['a plain static folder (unsupported stack)', () => writeProject({ 'index.html': '<h1>hi</h1>', 'css/site.css': 'body{margin:0}' })],
  ['an Express project that defines no routes', () => expressProject([], { 'lib.js': 'module.exports = 1;\n' })],
];

describe('Orchestrator.analyze when no routes are discovered', () => {
  for (const [name, make] of NO_ROUTE_PROJECTS) {
    it(`${name}: zero HTTP requests, a non-scored note, unchanged score, --fail-on info still passes`, async () => {
      const dir = make();
      const baseline = await Orchestrator.analyze(dir, { ...NON_INTERACTIVE, noDynamic: true });

      await withApp(appServing(['/', '/admin', '/health', '/api/users']), async (app) => {
        mockPorts = [app.port];
        const r = await Orchestrator.analyze(dir, NON_INTERACTIVE);

        expect(r.graph.routes).toEqual([]);
        expect(app.requests).toEqual([]);
        expect(mockPrompt).not.toHaveBeenCalled();

        const note = noteOf(r, NO_ROUTES_NOTE);
        expect(note).toBeDefined();
        expect(note!.severity).toBe('info');
        expect(r.findings.filter((f) => !(f as { note?: boolean }).note)).toEqual(baseline.findings);

        expect(r.score).toBe(baseline.score);
        expect(r.summary.critical).toBe(baseline.summary.critical);
        expect(r.summary.warning).toBe(baseline.summary.warning);
        expect(r.summary.info).toBe(baseline.summary.info);
        expect(r.summary.total).toBe(baseline.summary.total);
        expect(notesCount(r)).toBe(1);
        expect(ScoreCalculator.calculate(r.summary)).toBe(ScoreCalculator.calculate(baseline.summary));

        expect(shouldFail(r.summary, 'info')).toBe(shouldFail(baseline.summary, 'info'));
        expect(shouldFail(r.summary, 'warning')).toBe(false);
        expect((toCiJson(r, 'info') as { passed: boolean }).passed).toBe((toCiJson(baseline, 'info') as { passed: boolean }).passed);
      });
    });
  }

  it('a project with no findings at all: the note leaves score 100 and --fail-on info passes', async () => {
    const dir = writeProject({ 'index.html': '<h1>hi</h1>' });
    await withApp(appServing(['/']), async (app) => {
      mockPorts = [app.port];
      const r = await Orchestrator.analyze(dir, NON_INTERACTIVE);
      expect(app.requests).toEqual([]);
      expect(noteOf(r, NO_ROUTES_NOTE)).toBeDefined();
      expect(r.summary.total).toBe(0);
      expect(r.score).toBe(100);
      expect(shouldFail(r.summary, 'info')).toBe(false);
      expect((toCiJson(r, 'info') as { passed: boolean }).passed).toBe(true);
    });
  });

  it('an active scan with a token but no routes also sends zero requests and emits a note', async () => {
    const dir = writeProject({ 'index.html': '<h1>hi</h1>' });
    await withApp(appServing(['/', '/admin']), async (app) => {
      mockPorts = [app.port];
      const r = await Orchestrator.analyze(dir, { ...NON_INTERACTIVE, active: true, token: dummyJwt({ sub: 'user-42' }) });
      expect(app.requests).toEqual([]);
      expect(r.findings.some((f) => (f as { note?: boolean }).note === true && /No routes discovered/.test(f.title))).toBe(true);
    });
  });
});

describe('Orchestrator.analyze with discovered routes', () => {
  it('reports an odd-named open admin route and requests nothing it did not discover', async () => {
    const dir = expressProject([`app.get("/ping", ${handlerLine});`, `app.get("/backoffice", ${handlerLine});`, `app.get("/staff/console", ${handlerLine});`]);
    await withApp(appServing(['/ping', '/backoffice', '/staff/console']), async (app) => {
      mockPorts = [app.port];
      const r = await Orchestrator.analyze(dir, { ...NON_INTERACTIVE, aggressive: true });

      const paths = app.paths();
      expect(paths.filter((p) => !CONTROL_PATH.test(p)).every((p) => ['/ping', '/backoffice', '/staff/console'].includes(p))).toBe(true);
      expect(paths.filter((p) => CONTROL_PATH.test(p)).length).toBeLessThanOrEqual(1);
      for (const guessed of NEVER_GUESSED) expect(paths).not.toContain(guessed);

      const exposed = r.findings.filter((f) => f.rule === 'exposed-admin-route').map((f) => f.endpoint).sort();
      expect(exposed).toEqual(['/backoffice', '/staff/console']);
    });
  });

  it('the same odd-named routes answering 401/403/302 report nothing', async () => {
    const dir = expressProject([`app.get("/backoffice", ${handlerLine});`, `app.get("/staff/console", ${handlerLine});`]);
    await withApp(
      appServing([], (res, p) => {
        if (p === '/backoffice') return send(res, 401, '{}', 'application/json');
        if (p === '/staff/console') return send(res, 302, '', 'text/plain', { location: '/login' });
        send(res, 404, 'nf', 'text/plain');
      }),
      async (app) => {
        mockPorts = [app.port];
        const r = await Orchestrator.analyze(dir, { ...NON_INTERACTIVE, aggressive: true });
        expect(r.findings.filter((f) => f.rule === 'exposed-admin-route')).toEqual([]);
        expect(app.paths().filter((p) => CONTROL_PATH.test(p))).toEqual([]);
        expect(app.paths()).not.toContain('/login');
        expect(app.paths().every((p) => ['/backoffice', '/staff/console'].includes(p))).toBe(true);
      },
    );
  });
});

describe('path parameters: the active scan uses only ids from the supplied token claims', () => {
  const dir = () => expressProject([`app.get("/ping", ${handlerLine});`, `app.get("/users/:id", ${handlerLine});`]);
  const ownRecord = appServing(['/ping'], (res, p) =>
    p === '/users/user-42' ? send(res, 200, '{"id":"user-42","email":"a@example.test"}', 'application/json') : send(res, 404, 'nf', 'text/plain'),
  );

  it('requests /users/user-42 from the token sub, never /users/:id or an invented id', async () => {
    await withApp(ownRecord, async (app) => {
      mockPorts = [app.port];
      await Orchestrator.analyze(dir(), {
        ...NON_INTERACTIVE,
        noDynamic: true,
        active: true,
        token: dummyJwt({ sub: 'user-42' }),
      });
      const paths = app.paths();
      expect(paths).toContain('/users/user-42');
      expect(paths.every((p) => ['/ping', '/users/user-42'].includes(p))).toBe(true);
      expect(paths).not.toContain('/users/:id');
      expect(paths.filter((p) => p.startsWith('/users/') && p !== '/users/user-42')).toEqual([]);
    });
  });

  it('with a second identity, ids come only from the two supplied tokens', async () => {
    await withApp(ownRecord, async (app) => {
      mockPorts = [app.port];
      await Orchestrator.analyze(dir(), {
        ...NON_INTERACTIVE,
        noDynamic: true,
        active: true,
        token: dummyJwt({ sub: 'user-42' }),
        tokenB: dummyJwt({ sub: 'user-43' }),
      });
      const userPaths = new Set(app.paths().filter((p) => p.startsWith('/users/')));
      expect(userPaths.has('/users/user-42')).toBe(true);
      for (const p of userPaths) expect(['/users/user-42', '/users/user-43']).toContain(p);
    });
  });

  it('a token that cannot fill the parameter means the route is skipped, not guessed', async () => {
    await withApp(ownRecord, async (app) => {
      mockPorts = [app.port];
      await Orchestrator.analyze(dir(), {
        ...NON_INTERACTIVE,
        noDynamic: true,
        active: true,
        token: dummyJwt({ role: 'user' }),
      });
      expect(app.paths().filter((p) => p.startsWith('/users'))).toEqual([]);
    });
  });

  it('the dynamic scan alone never requests the parameterised route', async () => {
    await withApp(appServing(['/ping', '/users/1', '/users/user-42']), async (app) => {
      mockPorts = [app.port];
      await Orchestrator.analyze(dir(), NON_INTERACTIVE);
      expect(app.paths().filter((p) => p.startsWith('/users'))).toEqual([]);
      expect(app.paths()).toContain('/ping');
    });
  });
});
