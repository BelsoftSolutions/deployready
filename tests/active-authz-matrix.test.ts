/**
 * Policy-driven authorization matrix (0.6) against a real loopback multi-role,
 * multi-tenant app: every vulnerability class has a vulnerable and a fixed
 * variant, and each flag must produce its own class and nothing else.
 */
import { startAuthzApp, authzActiveConfig, TOKENS, type Vulns, type AuthzApp } from './helpers/authzApp';
import { authzSettings } from '../src/active/projectConfig';
import { resolveIdentities } from '../src/active/identities';
import { previewAuthz, runAuthz, planAuthz } from '../src/active/authzEngine';
import { createActiveHttpAdapter } from '../src/active/httpAdapter';
import type { SafetyLevel } from '../src/active/safety';
import type { AuthzTestClass } from '../src/active/authzTypes';

async function matrix(app: AuthzApp, level: SafetyLevel = 'stateful', over: Record<string, unknown> = {}, cfg = authzActiveConfig()) {
  const s = authzSettings(cfg, 'test');
  expect(s.problems).toEqual([]);
  const identities = await resolveIdentities(s.identities, {});
  return runAuthz(
    { policy: s.policy!, identities, routes: [], safetyLevel: level, maxRequests: 5000, baseUrl: app.baseUrl, ...over },
    createActiveHttpAdapter({ baseUrl: app.baseUrl, maxRequests: 5000 }),
  );
}

async function withAuthzApp<T>(v: Vulns, fn: (app: AuthzApp) => Promise<T>): Promise<T> {
  const app = await startAuthzApp(v);
  try {
    return await fn(app);
  } finally {
    await app.close();
  }
}

describe('authorization matrix: fixed app', () => {
  it('reports no violation, and proves the denials and the allowed accesses', async () => {
    await withAuthzApp({}, async (app) => {
      const { matrix: m, findings } = await matrix(app);
      expect(findings).toEqual([]);
      expect(m.summary.violation).toBe(0);
      expect(m.summary.inconclusive).toBe(0);
      const classes = new Set(m.cells.filter((c) => c.verdict === 'denied-as-expected').map((c) => c.testClass));
      for (const cls of ['missing-auth', 'vertical', 'horizontal', 'cross-tenant', 'nested-id', 'list-filter', 'batch', 'export', 'cross-write', 'cross-delete', 'mass-assignment', 'graphql-introspection', 'graphql-id'] as AuthzTestClass[]) {
        expect(classes).toContain(cls);
      }
      expect(m.cells.some((c) => c.identity === 'admin' && c.verdict === 'allowed-as-expected' && c.target === 'alice')).toBe(true);
      expect(m.cells.some((c) => c.identity === 'alice' && c.testClass === 'own-access' && c.verdict === 'allowed-as-expected')).toBe(true);
    });
  });
});

const CASES: [keyof Vulns, AuthzTestClass[], string[]][] = [
  ['bola', ['horizontal', 'cross-tenant'], ['authz-bola', 'authz-cross-tenant']],
  ['missingAuth', ['missing-auth', 'horizontal', 'cross-tenant'], ['authz-missing-auth', 'authz-bola', 'authz-cross-tenant']],
  ['listLeak', ['list-filter'], ['authz-bola', 'authz-cross-tenant']],
  ['queryId', ['horizontal', 'cross-tenant'], ['authz-bola', 'authz-cross-tenant']],
  ['batch', ['batch'], ['authz-bola', 'authz-cross-tenant']],
  ['exportLeak', ['export'], ['authz-bola', 'authz-cross-tenant']],
  ['bfla', ['vertical'], ['authz-bfla']],
  ['crossTenant', ['cross-tenant', 'nested-id'], ['authz-cross-tenant']],
  ['nested', ['nested-id'], ['authz-cross-tenant']],
  ['crossWrite', ['cross-write'], ['authz-unauthorized-write']],
  ['crossDelete', ['cross-delete'], ['authz-unauthorized-write']],
  ['massAssign', ['mass-assignment'], ['authz-mass-assignment']],
  ['privEsc', ['privilege-escalation'], ['authz-privilege-escalation']],
  ['introspection', ['graphql-introspection'], ['graphql-introspection']],
  ['graphqlBola', ['graphql-id'], ['authz-bola', 'authz-cross-tenant']],
];

describe('authorization matrix: each vulnerable variant yields exactly its class', () => {
  it.each(CASES)('%s', async (flag, classes, rules) => {
    await withAuthzApp({ [flag]: true }, async (app) => {
      const { matrix: m, findings } = await matrix(app);
      const got = new Set(m.cells.filter((c) => c.verdict === 'violation').map((c) => c.testClass));
      expect([...got].sort()).toEqual([...classes].sort());
      expect([...new Set(findings.map((f) => f.rule))].sort()).toEqual([...rules].sort());
      expect(m.summary.inconclusive).toBe(0);
      for (const c of m.cells.filter((x) => x.verdict === 'violation')) {
        expect(c.statement).toMatch(/could|includes/);
        expect(c.findingId).toBeDefined();
      }
    });
  });

  it('writes a plain-English statement, a masked proof, and never a credential', async () => {
    await withAuthzApp({ bola: true }, async (app) => {
      const { matrix: m, findings } = await matrix(app);
      const cell = m.cells.find((c) => c.verdict === 'violation' && c.identity === 'alice' && c.target === 'bob')!;
      expect(cell.statement).toMatch(/^User "alice" \(role user, tenant acme\) could read invoices of "bob"/);
      expect(cell.statement).not.toContain('bob.customer@example.test');
      const text = JSON.stringify({ m, findings });
      for (const t of Object.values(TOKENS)) expect(text).not.toContain(t);
      expect(text).not.toContain('bob.customer@example.test');
      const f = findings.find((x) => x.rule === 'authz-bola')!;
      expect(f.endpoint).toBe('GET /api/invoices/:id');
      expect(f.proof!.request).toContain('$ALICE_AUTH');
      expect(f.severity).toBe('critical');
    });
  });
});

describe('authorization matrix: safety', () => {
  it('read-only never sends a write, and lists write cells as untested', async () => {
    await withAuthzApp({ crossWrite: true, crossDelete: true, massAssign: true }, async (app) => {
      const { matrix: m } = await matrix(app, 'read-only');
      const writes = app.requests.filter((r) => r.method !== 'GET' && !(r.method === 'POST' && (r.path === '/graphql' || r.path === '/api/invoices/batch-get')));
      expect(writes).toEqual([]);
      expect(m.summary.violation).toBe(0);
      const patch = m.cells.filter((c) => c.route === 'PATCH /api/invoices/:id');
      expect(patch.length).toBeGreaterThan(0);
      expect(patch.every((c) => c.verdict === 'untested' && /stateful/.test(c.reason))).toBe(true);
    });
  });

  it('a POST batch read is only sent when declared side-effect free', async () => {
    await withAuthzApp({ batch: true }, async (app) => {
      const cfg = authzActiveConfig();
      const res = (cfg.policy as { resources: { routes: unknown[] }[] }).resources[0]!;
      res.routes = res.routes.map((r) => (typeof r === 'object' ? { route: 'POST /api/invoices/batch-get', batchField: 'ids' } : r));
      const { matrix: m } = await matrix(app, 'read-only', {}, cfg);
      expect(app.requests.some((r) => r.path === '/api/invoices/batch-get')).toBe(false);
      expect(m.cells.filter((c) => c.route.includes('batch-get')).every((c) => c.verdict === 'untested')).toBe(true);
    });
  });

  it('the request budget stops the run and marks the rest untested', async () => {
    await withAuthzApp({ bola: true }, async (app) => {
      const { matrix: m } = await matrix(app, 'read-only', { maxRequests: 10 });
      expect(app.requests.length).toBeLessThanOrEqual(10);
      expect(m.cells.some((c) => c.verdict === 'untested' && /budget/.test(c.reason))).toBe(true);
    });
  });

  it('unsafeRoutes are never requested, not even as a read-back', async () => {
    await withAuthzApp({}, async (app) => {
      await matrix(app, 'stateful', { unsafeRoutes: ['/api/invoices*'] });
      expect(app.requests.some((r) => r.path.startsWith('/api/invoices'))).toBe(false);
    });
    await withAuthzApp({ crossWrite: true }, async (app) => {
      const { matrix: m } = await matrix(app, 'stateful', { unsafeRoutes: ['GET /api/invoices/*'] });
      expect(app.requests.some((r) => r.method === 'GET' && /^\/api\/invoices\/[^/]+$/.test(r.path))).toBe(false);
      expect(m.cells.filter((c) => c.route === 'PATCH /api/invoices/:id' && c.identity !== 'admin').every((c) => c.verdict === 'untested')).toBe(true);
    });
  });

  it('the dry run lists the matrix plan and sends nothing', async () => {
    await withAuthzApp({}, async (app) => {
      const s = authzSettings(authzActiveConfig(), 'test');
      const identities = await resolveIdentities(s.identities, { planOnly: true });
      const dry = previewAuthz({ policy: s.policy!, identities, routes: [], safetyLevel: 'read-only', baseUrl: app.baseUrl });
      expect(app.requests).toEqual([]);
      expect(dry.lines.join('\n')).toMatch(/\[horizontal\] alice \(user\) → bob's record: GET \/api\/invoices\/inv_b {2}expect deny/);
      expect(dry.lines.join('\n')).toMatch(/PATCH \/api\/invoices\/:id as alice: .*stateful/);
      expect(dry.matrix.cells.every((c) => c.verdict === 'untested')).toBe(true);
    });
  });
});

describe('authorization matrix: precision', () => {
  it('an SPA fallback page answering 200 on an admin route is not a violation', async () => {
    const http = await import('http');
    const server = http.createServer((req, res) => {
      const admin = req.headers.authorization === `Bearer ${TOKENS.admin}`;
      if (req.url === '/admin/stats' && admin) {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ revenue: 99881.5, topCustomer: 'alice.customer@example.test' }));
      }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<!doctype html><html><body><div id="root"></div><script src="/app.js"></script></body></html>');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const baseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const cfg = authzActiveConfig();
      (cfg.policy as { resources: unknown[]; graphql?: unknown }).resources = [{ name: 'admin-stats', routes: ['GET /admin/stats'], access: { anonymous: 'none', user: 'none', admin: 'manage' } }];
      delete (cfg.policy as { graphql?: unknown }).graphql;
      const s = authzSettings(cfg, 'test');
      const { matrix: m, findings } = await runAuthz(
        { policy: s.policy!, identities: await resolveIdentities(s.identities, {}), routes: [], safetyLevel: 'read-only', baseUrl },
        createActiveHttpAdapter({ baseUrl }),
      );
      expect(findings).toEqual([]);
      expect(m.summary.violation).toBe(0);
      expect(m.cells.filter((c) => c.expected === 'deny').every((c) => c.verdict === 'inconclusive')).toBe(true);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it('a route whose ids no identity declares is untested, never guessed', () => {
    const cfg = authzActiveConfig();
    (cfg.policy as { resources: unknown[] }).resources = [{ name: 'orders', routes: ['GET /api/orders/:id'], access: { user: 'own' } }];
    const s = authzSettings(cfg, 'test');
    const plan = planAuthz({ policy: s.policy!, identities: [{ name: 'alice', role: 'user', provider: { name: 'alice', role: 'user', headers: async () => ({}) } }], routes: [{ method: 'GET', path: '/api/other', file: 'x.js', guarded: false }], safetyLevel: 'read-only' });
    expect(plan.cases).toEqual([]);
    expect(plan.cells[0]!.verdict).toBe('untested');
    expect(plan.cells[0]!.reason).toMatch(/never invented/);
    expect(plan.uncovered).toEqual(['GET /api/other']);
  });
});
