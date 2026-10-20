import { PROBE_PATHS } from '../src/dynamic/commonPaths/signatures';
import { html, json, probeRoutes, send, text, withServer } from './helpers/probeServer';
import type { Reply, RouteMap } from './helpers/probeServer';
import { runCommonPathProbe } from '../src/dynamic/commonPaths/prober';

const SPA = html('<!doctype html><html><head><title>My App</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>');

const outcomeOf = (report: { probed: { path: string; outcome: string }[] }, path: string) =>
  report.probed.find((p) => p.path === path)?.outcome;

describe('false-positive traps', () => {
  it('catch-all SPA: same 200 HTML for everything, nothing found, all not-proven', async () => {
    const { findings, report } = await probeRoutes({}, {}, SPA);
    expect(findings).toEqual([]);
    expect(report.probed).toHaveLength(16);
    expect(report.probed.every((p) => p.status === 200 && p.outcome === 'not-proven')).toBe(true);
    for (const p of ['/.env', '/admin', '/console']) {
      expect(outcomeOf(report, p)).toBe('not-proven');
    }
    expect(report.probed[0]?.reason).toMatch(/catch-all/);
  });

  it('catch-all SPA whose body differs per path (echoes the URL) is still recognised by shape', async () => {
    const { findings } = await withServer(
      (req, res) =>
        send(res, html(`<!doctype html><html><head><title>My App</title></head><body><div id="root" data-path="${req.url}"></div><script></script></body></html>`)),
      async (baseUrl) => runCommonPathProbe(baseUrl, { exclude: [], delayMs: 0 }),
    );
    expect(findings).toEqual([]);
  });

  it('JSON 200 for every unknown path: no finding for /actuator, /actuator/env, /metrics', async () => {
    const same = json({ status: 'ok', data: null });
    const { findings, report } = await probeRoutes({}, {}, same);
    expect(findings).toEqual([]);
    for (const p of ['/actuator', '/actuator/env', '/metrics']) expect(outcomeOf(report, p)).toBe('not-proven');
  });

  it('JSON 200 with the same keys but different values and length is still the catch-all (shape)', async () => {
    const { findings } = await withServer(
      (req, res) => send(res, json({ path: req.url, message: 'x'.repeat((req.url ?? '').length * 3), ok: true })),
      async (baseUrl) => runCommonPathProbe(baseUrl, { exclude: [], delayMs: 0 }),
    );
    expect(findings).toEqual([]);
  });

  it('an HTML /.env page, even one containing A=B text, is not a finding', async () => {
    const routes: RouteMap = {
      '/.env': html('<html><head><title>Config</title></head><body>A=B\nC=D\nE=F\n</body></html>'),
    };
    const { findings, report } = await probeRoutes(routes);
    expect(findings).toEqual([]);
    expect(report.probed.find((p) => p.path === '/.env')).toMatchObject({
      outcome: 'not-proven',
      reason: 'HTML, not the expected content',
    });
  });

  it('a /.env served as text/plain whose body starts with "<" is HTML-ish and not a finding', async () => {
    const { findings } = await probeRoutes({ '/.env': text('<!-- x -->\nA=B\nC=D\n') });
    expect(findings).toEqual([]);
  });

  it('/admin and /.env redirecting 302 to /login: protected, no finding, /login never requested', async () => {
    const redirect: Reply = { status: 302, headers: { location: '/login' }, body: '' };
    const { findings, report, seen } = await probeRoutes({ '/admin': redirect, '/.env': redirect });
    expect(findings).toEqual([]);
    expect(report.probed.find((p) => p.path === '/admin')).toMatchObject({ outcome: 'protected', status: 302 });
    expect(report.probed.find((p) => p.path === '/.env')).toMatchObject({ outcome: 'protected' });
    expect(report.probed.find((p) => p.path === '/admin')?.reason).toMatch(/redirect to login: protected, not exposed/);
    expect(seen.map((r) => r.path)).not.toContain('/login');
  });

  it('a redirect elsewhere is protected "redirect, not followed" and the target is never requested', async () => {
    const { report, seen } = await probeRoutes({ '/admin': { status: 301, headers: { location: '/somewhere-else' } } });
    expect(report.probed.find((p) => p.path === '/admin')).toMatchObject({
      outcome: 'protected',
      reason: 'redirect, not followed',
    });
    expect(seen.map((r) => r.path)).not.toContain('/somewhere-else');
  });

  it.each([401, 403])('/admin returning %i is protected, no finding', async (status) => {
    const { findings, report } = await probeRoutes({ '/admin': { status, type: 'text/plain', body: 'denied' } });
    expect(findings).toEqual([]);
    expect(report.probed.find((p) => p.path === '/admin')).toMatchObject({ outcome: 'protected', status });
  });

  it('/admin returning a login form with a password input is not proven', async () => {
    const page = html('<html><head><title>Admin dashboard</title></head><body><form><input name="u"><input TYPE=\'password\' name="p"></form></body></html>');
    const { findings, report } = await probeRoutes({ '/admin': page });
    expect(findings).toEqual([]);
    expect(report.probed.find((p) => p.path === '/admin')).toMatchObject({ outcome: 'not-proven', reason: 'login page' });
  });

  it('/.env with prose or fewer than 50% KEY=VALUE lines is not a finding', async () => {
    const prose = text('Welcome to my site.\nNothing to see.\nA=B appears once.\nSorry.\n');
    expect((await probeRoutes({ '/.env': prose })).findings).toEqual([]);
    const sparse = text('A=1\nthis line is prose\nneither is this\nnor this\n');
    expect((await probeRoutes({ '/.env': sparse })).findings).toEqual([]);
  });

  it('an admin page identical to the control is not a finding', async () => {
    const page = html('<html><head><title>Admin</title></head><body><h1>Admin</h1></body></html>');
    const { findings, report } = await probeRoutes({ '/admin': page }, {}, page);
    expect(findings).toEqual([]);
    expect(outcomeOf(report, '/admin')).toBe('not-proven');
  });

  it('404, 410, 405 and 500 are not-found with no finding', async () => {
    const routes: RouteMap = {};
    [404, 410, 405, 500].forEach((status, i) => {
      routes[PROBE_PATHS[i]!.path] = { status, type: 'text/plain', body: 'x' };
    });
    const { findings, report } = await probeRoutes(routes);
    expect(findings).toEqual([]);
    expect(report.probed.slice(0, 4).map((p) => p.outcome)).toEqual(['not-found', 'not-found', 'not-found', 'not-found']);
  });

  it('a real finding is still reported when the control is a 200 catch-all that differs from it', async () => {
    const env = text('DB_HOST=localhost\nPORT=3000\n');
    const { findings } = await probeRoutes({ '/.env': env }, {}, SPA);
    expect(findings.map((f) => f.endpoint)).toEqual(['/.env']);
  });
});
