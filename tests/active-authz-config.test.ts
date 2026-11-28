/**
 * Identities, policy config, `policy init`, the Orchestrator wiring
 * (.deployready.json → matrix in the JSON/markdown/HTML reports) and the
 * Verifier re-check of a matrix finding.
 */
import * as fs from 'fs';
import * as path from 'path';
import { saveSession } from '../src/auth/session';
import {
  authPlaceholder,
  clearSessionProviders,
  parseIdentityConfigs,
  registerSessionProvider,
  resolveIdentities,
} from '../src/active/identities';
import { draftPolicy, expectedAllowed, parsePolicy, parseRouteSpec, routeMatches } from '../src/active/policy';
import { buildDraftPolicy, initPolicy } from '../src/active/policyInit';
import { authzMarkdown, authzHtml } from '../src/active/authzReport';
import { authzActiveConfig, startAuthzApp, TOKENS } from './helpers/authzApp';
import { expressProject, writeProject } from './helpers/dummyApp';
import type { Route } from '../src/types';

let mockPorts: number[] = [];
let mockActive: Record<string, unknown> = {};
jest.mock('../src/config/ConfigManager', () => ({
  ConfigManager: { exists: async () => true, load: async () => ({ defaultPorts: mockPorts, model: 'none', active: mockActive }) },
}));
jest.mock('inquirer', () => ({ prompt: jest.fn() }));

import { Orchestrator } from '../src/core/Orchestrator';
import { Verifier } from '../src/core/Verifier';
import { toCiJson } from '../src/core/CiGate';

const route = (method: string, p: string): Route => ({ method, path: p, file: 'server.js', guarded: false });

describe('identities', () => {
  afterEach(() => clearSessionProviders());

  it('validates entries and refuses an unrelated tokenEnv', () => {
    const { identities, problems } = parseIdentityConfigs([
      { name: 'alice', role: 'user', tokenEnv: 'ALICE_TOKEN' },
      { name: 'leak', role: 'user', tokenEnv: 'AWS_SECRET_ACCESS_KEY' },
      { name: 'nocred', role: 'user' },
      { name: 'two', role: 'user', token: 'x', tokenEnv: 'X_TOKEN' },
      { name: 'alice', role: 'admin', token: 'y' },
      { name: 'anonymous' },
    ]);
    expect(identities.map((i) => i.name)).toEqual(['alice', 'anonymous']);
    expect(problems.join('\n')).toMatch(/AWS_SECRET_ACCESS_KEY.*must contain TOKEN/);
    expect(problems.join('\n')).toMatch(/nocred.*no credential/);
    expect(problems.join('\n')).toMatch(/only one of/);
    expect(problems.join('\n')).toMatch(/duplicate/);
  });

  it('reads tokens from the environment, adds --token/--token-b as identities, always has anonymous', async () => {
    const ids = await resolveIdentities(parseIdentityConfigs([{ name: 'alice', role: 'user', tokenEnv: 'ALICE_TOKEN' }, { name: 'bob', role: 'user', tokenEnv: 'BOB_TOKEN' }]).identities, {
      env: { ALICE_TOKEN: 'a-secret' },
      cliToken: 'cli-a',
      cliTokenB: 'cli-b',
    });
    expect(ids.map((i) => i.name)).toEqual(['anonymous', 'alice', 'bob', 'token', 'token-b']);
    expect(await ids[1]!.provider!.headers()).toEqual({ Authorization: 'Bearer a-secret' });
    expect(ids[2]!.unavailable).toMatch(/BOB_TOKEN is not set/);
    expect(await ids[0]!.provider!.headers()).toEqual({});
    expect(authPlaceholder('other-tenant')).toBe('$OTHER_TENANT_AUTH');
  });

  it('a session name uses the saved Playwright session (cookie for the target only); a missing one is unavailable', async () => {
    const root = writeProject({});
    saveSession(root, 'alice-web', { cookies: [{ name: 'sid', value: 'cookie-value-1', domain: '127.0.0.1', path: '/', expires: -1 } as never], origins: [] });
    const cfg = parseIdentityConfigs([
      { name: 'alice', role: 'user', session: 'alice-web' },
      { name: 'bob', role: 'user', session: 'bob-web' },
      { name: 'bad', role: 'user', session: '../etc/passwd' },
    ]);
    expect(cfg.problems.join(' ')).toMatch(/identities\[2\]\.session: Session name/);
    const ids = await resolveIdentities(cfg.identities, { baseUrl: 'http://127.0.0.1:4010', projectPath: root });
    const alice = ids.find((i) => i.name === 'alice')!;
    expect(await alice.provider!.headers()).toEqual({ Cookie: 'sid=cookie-value-1' });
    expect(ids.find((i) => i.name === 'bob')!.unavailable).toMatch(/session unusable/);
    // A dry run never logs in.
    const plan = await resolveIdentities(cfg.identities, { planOnly: true });
    await expect(plan.find((i) => i.name === 'alice')!.provider!.headers()).rejects.toThrow(/plan-only/);
  });

  it('other session providers plug in through registerSessionProvider', async () => {
    registerSessionProvider('custom', async (c) => ({ name: c.name, role: c.role, headers: async () => ({ Cookie: 'x=1' }) }));
    const ids = await resolveIdentities(parseIdentityConfigs([{ name: 'u', role: 'user', session: { provider: 'custom' } }, { name: 'v', role: 'user', session: { provider: 'nope' } }]).identities);
    expect(await ids.find((i) => i.name === 'u')!.provider!.headers()).toEqual({ Cookie: 'x=1' });
    expect(ids.find((i) => i.name === 'v')!.unavailable).toMatch(/no "nope" session provider/);
  });
});

describe('policy', () => {
  it('parses routes, query bindings and levels; rejects GraphQL mutations', () => {
    expect(parseRouteSpec('GET /api/orders?userId=:userId')).toMatchObject({ method: 'GET', path: '/api/orders', query: { userId: ':userId' } });
    expect(parseRouteSpec('/users/{id}')!.path).toBe('/users/:id');
    expect(routeMatches(parseRouteSpec('GET /users/:id')!, 'get', '/users/[uid]')).toBe(true);
    const { policy, problems } = parsePolicy({
      resources: [{ name: 'a', routes: ['GET /a/:id', 'BREW /x'], access: { user: 'own', admin: 'everything' } }],
      graphql: { queries: [{ resource: 'a', query: 'mutation { drop }' }] },
    });
    expect(policy!.resources[0]!.routes).toHaveLength(1);
    expect(problems.join(' ')).toMatch(/BREW/);
    expect(problems.join(' ')).toMatch(/admin must be one of/);
    expect(problems.join(' ')).toMatch(/only queries are sent/);
  });

  it('expected decisions follow none | read | own | manage and tenant scoping', () => {
    const r = parsePolicy({ resources: [{ name: 'x', routes: ['GET /x/:id'], access: { anonymous: 'none', viewer: 'read', user: 'own', admin: 'manage' } }] }).policy!.resources[0]!;
    expect(expectedAllowed(r, 'anonymous', 'read', 'other')).toBe(false);
    expect(expectedAllowed(r, 'viewer', 'read', 'other')).toBe(true);
    expect(expectedAllowed(r, 'viewer', 'write', 'other')).toBe(false);
    expect(expectedAllowed(r, 'user', 'write', 'own')).toBe(true);
    expect(expectedAllowed(r, 'user', 'read', 'other')).toBe(false);
    expect(expectedAllowed(r, 'admin', 'write', 'other')).toBe(true);
    expect(expectedAllowed(r, 'admin', 'read', 'other-tenant')).toBe(false);
  });

  it('drafts admin-only, own, and public-read resources from routes', () => {
    const d = draftPolicy([
      route('GET', '/admin/users'),
      route('GET', '/api/users/:id'),
      route('GET', '/api/products'),
      route('GET', '/api/invoices/:id'),
      route('POST', '/api/invoices/batch'),
      route('GET', '/api/invoices/export'),
      route('POST', '/login'),
      route('POST', '/graphql'),
    ]);
    const by = Object.fromEntries(d.resources.map((r) => [r.name, r]));
    expect(by['admin-users']!.access).toEqual({ anonymous: 'none', user: 'none', admin: 'manage' });
    expect(by.users!.access.user).toBe('own');
    expect(by.products!.access).toMatchObject({ anonymous: 'read', user: 'read' });
    expect(by.products!.tenantScoped).toBe(false);
    expect(by.invoices!.routes).toContainEqual({ route: 'POST /api/invoices/batch', batchField: 'ids', sideEffectFree: false });
    expect(by.invoices!.routes).toContainEqual({ route: 'GET /api/invoices/export', sideEffectFree: false });
    expect(d.excluded.map((e) => e.route)).toContain('POST /login');
    expect(d.graphqlEndpoint).toBe('/graphql');
  });

  it('policy init writes a clearly marked draft, keeps other keys, and will not overwrite', async () => {
    const dir = writeProject({ '.deployready.json': JSON.stringify({ publicTables: ['posts'] }) });
    const res = await initPolicy(dir, [route('GET', '/api/users/:id')], { now: new Date('2026-11-28T00:00:00Z') });
    const written = JSON.parse(fs.readFileSync(path.join(dir, '.deployready.json'), 'utf8'));
    expect(res.written).toBe(true);
    expect(written.publicTables).toEqual(['posts']);
    expect(written.active.policy.draft).toBe(true);
    expect(written.active.policy._comment).toMatch(/^DRAFT generated by `deployready policy init` on 2026-11-28/);
    expect(written.active.identities.map((i: { name: string }) => i.name)).toEqual(['anonymous', 'user', 'user2', 'admin', 'other-tenant']);
    await expect(initPolicy(dir, [])).rejects.toThrow(/already has an active.policy/);
    expect(buildDraftPolicy([]).draft).toBe(true);
  });
});

describe('Orchestrator + reports + Verifier', () => {
  beforeEach(() => {
    mockActive = {};
  });

  const project = (active: Record<string, unknown>) =>
    expressProject(['app.get("/api/invoices/:id", (req, res) => res.json({}));', 'app.get("/api/unlisted", (req, res) => res.json({}));'], {
      '.deployready.json': JSON.stringify({ active }),
    });

  it('runs the matrix from .deployready.json with --active and no --token, and reports it in JSON, markdown and HTML', async () => {
    const app = await startAuthzApp({ bola: true });
    try {
      const dir = project(authzActiveConfig());
      const report = await Orchestrator.analyze(dir, { yes: true, noAi: true, json: true, noDynamic: true, active: true, activeUrl: app.baseUrl });
      expect(report.authz).toBeDefined();
      expect(report.authz!.summary.violation).toBeGreaterThan(0);
      expect(report.authz!.uncoveredRoutes).toContain('GET /api/unlisted');
      expect(report.findings.some((f) => f.rule === 'authz-bola')).toBe(true);
      expect(app.requests.every((r) => r.method === 'GET' || r.method === 'POST')).toBe(true); // read-only default
      const json = toCiJson(report, 'none') as { authz?: { cells: unknown[] } };
      expect(json.authz!.cells.length).toBe(report.authz!.cells.length);
      const md = authzMarkdown(report.authz).join('\n');
      expect(md).toMatch(/## Authorization matrix/);
      expect(md).toMatch(/\*\*VIOLATION\*\* — User "alice"/);
      expect(authzHtml(report.authz)).toMatch(/<h2>Authorization matrix<\/h2>/);
      for (const t of Object.values(TOKENS)) expect(JSON.stringify(report)).not.toContain(t);
      expect(report.coverage!.find((c) => c.kind === 'active')?.state).toBe('passed');

      // Verifier: still present while vulnerable...
      const f = report.findings.find((x) => x.rule === 'authz-bola')!;
      const again = await Verifier.verify(f, { target: dir, authz: { baseUrl: app.baseUrl, routes: report.graph.routes } });
      expect(again.status).toBe('still-present');
    } finally {
      await app.close();
    }
  });

  it('the Verifier reports fixed once the app enforces the policy', async () => {
    const app = await startAuthzApp({});
    try {
      const dir = project(authzActiveConfig());
      const f = { id: 'x', rule: 'authz-bola', title: 't', severity: 'critical' as const, category: 'security' as const, source: 'dynamic' as const, description: '', recommendation: '', endpoint: 'GET /api/invoices/:id' };
      const res = await Verifier.verify(f, { target: dir, authz: { baseUrl: app.baseUrl, routes: [] } });
      expect(res.status).toBe('fixed');
    } finally {
      await app.close();
    }
  });

  it('refuses a draft policy and sends nothing', async () => {
    const app = await startAuthzApp({ bola: true });
    try {
      const cfg = authzActiveConfig();
      (cfg.policy as { draft: boolean }).draft = true;
      const report = await Orchestrator.analyze(project(cfg), { yes: true, noAi: true, json: true, noDynamic: true, active: true, activeUrl: app.baseUrl });
      expect(app.requests).toEqual([]);
      expect(report.coverage!.find((c) => c.kind === 'active')?.reason).toMatch(/draft/);
    } finally {
      await app.close();
    }
  });

  it('stateful is refused without disposableEnvironment; --dry-run lists the matrix and sends nothing', async () => {
    const app = await startAuthzApp({});
    try {
      const dir = project(authzActiveConfig());
      await Orchestrator.analyze(dir, { yes: true, noAi: true, json: true, noDynamic: true, active: true, activeUrl: app.baseUrl, safetyLevel: 'stateful' });
      expect(app.requests).toEqual([]);
      const dry = await Orchestrator.analyze(dir, { yes: true, noAi: true, json: true, noDynamic: true, active: true, activeUrl: app.baseUrl, dryRun: true });
      expect(app.requests).toEqual([]);
      expect(dry.authz!.cells.every((c) => c.verdict === 'untested')).toBe(true);
      // With a disposable environment declared, stateful runs and writes.
      await Orchestrator.analyze(project(authzActiveConfig({ disposableEnvironment: true })), { yes: true, noAi: true, json: true, noDynamic: true, active: true, activeUrl: app.baseUrl, safetyLevel: 'stateful' });
      expect(app.requests.some((r) => r.method === 'PATCH')).toBe(true);
    } finally {
      await app.close();
    }
  });

  it('without a policy, --token keeps the token-based scan', async () => {
    const report = await Orchestrator.analyze(project({}), { yes: true, noAi: true, json: true, noDynamic: true, active: true, token: 'not-a-jwt' });
    expect(report.authz).toBeUndefined();
    expect(report.coverage!.find((c) => c.kind === 'active')?.reason).toMatch(/not a valid JWT/);
  });
});
