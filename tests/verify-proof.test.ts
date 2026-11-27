/**
 * 0.4.0 "proof, not guesses": Proof on live findings, the Verifier's
 * fixed / still-present / inconclusive rules for active findings, the
 * unauthenticated write-route probe, and the active-scan ownership guard.
 */
import * as http from 'http';
import type { AddressInfo } from 'net';
import { buildProof, curlCommand, proofBody, PROOF_BODY_MAX } from '../src/dynamic/proof';
import { runActiveScan, type ActiveObservation, type HttpFn } from '../src/active/runner';
import { decodeJwt } from '../src/active/jwt';
import { assertActiveTarget, parseOwnedHosts } from '../src/active/scope';
import { createActiveHttpAdapter } from '../src/active/httpAdapter';
import { planMutationProbes, runMutationProbes, MUTATION_RULE } from '../src/active/mutationProbe';
import { Verifier } from '../src/core/Verifier';
import { makeFinding } from '../src/utils/finding';
import { toCiJson } from '../src/core/CiGate';
import { ExportManager } from '../src/ui/ExportManager';
import { HtmlReporter } from '../src/ui/HtmlReporter';
import { IssuePresenter } from '../src/ui/IssuePresenter';
import type { Finding, Route, ScanReport } from '../src/types';

function makeJwt(payload: object, sig = 'sigABCDEFGHIJKLMNOP'): string {
  const seg = (o: object) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
  return `${seg({ alg: 'HS256', typ: 'JWT' })}.${seg(payload)}.${sig}`;
}
const tokenA = makeJwt({ sub: '1', org_id: 'o1', role: 'user' });
const tokenB = makeJwt({ sub: '2', org_id: 'o2', role: 'user' });

const users: Record<string, object> = { '1': { id: '1', email: 'a@x.io' }, '2': { id: '2', email: 'b@x.io' } };

/** Configurable fake app: each flaw can be switched on/off, or the app made to fail. */
function fakeApp(o: { verifySig?: boolean; ownerCheck?: boolean; roleCheck?: boolean; down?: boolean; ownerBroken?: boolean }): HttpFn {
  return async (req) => {
    if (o.down) throw new Error('ECONNREFUSED');
    const token = (req.headers.Authorization ?? '').replace('Bearer ', '');
    const d = token ? decodeJwt(token) : null;
    if (!d) return { status: 401, bodyText: '{"error":"unauthorized"}' };
    if (o.verifySig && (d.header.alg === 'none' || !token.endsWith('sigABCDEFGHIJKLMNOP'))) {
      return { status: 401, bodyText: '{"error":"bad signature"}' };
    }
    const m = /^\/api\/users\/([^/]+)$/.exec(req.path);
    if (m) {
      if (o.ownerBroken && d.payload.sub === '2') return { status: 500, bodyText: 'oops' };
      if (o.ownerCheck && m[1] !== d.payload.sub) return { status: 403, bodyText: '{"error":"forbidden"}' };
      const u = users[m[1]!];
      return u ? { status: 200, bodyText: JSON.stringify(u) } : { status: 404, bodyText: '{}' };
    }
    if (req.path === '/api/admin') {
      return d.payload.role === 'admin' && !o.roleCheck ? { status: 200, bodyText: '{"cfg":1}' } : { status: 403, bodyText: '{}' };
    }
    return { status: 404, bodyText: '' };
  };
}

const routes: Route[] = [
  { method: 'GET', path: '/api/users/:id', file: 'a.js', guarded: true },
  { method: 'GET', path: '/api/admin', file: 'a.js', guarded: true },
];
const base = 'http://localhost:3000';
const activeCtx = (httpFn: HttpFn, over: Partial<{ tokenB: string | undefined }> = {}) => ({
  target: '/p',
  active: { baseUrl: base, routes, token: tokenA, tokenB: 'tokenB' in over ? over.tokenB : tokenB, http: httpFn },
});

function finding(rule: string, endpoint: string): Finding {
  return makeFinding({ rule, title: 't', severity: 'critical', category: 'security', source: 'dynamic', endpoint, description: 'd', recommendation: 'r' });
}

describe('proof builder', () => {
  it('writes a curl command that names tokens by variable and redacts anything secret', () => {
    expect(curlCommand({ method: 'GET', url: 'http://localhost:3000/a', auth: '$TOKEN' })).toBe(
      `curl -i --oauth2-bearer "$TOKEN" 'http://localhost:3000/a'`,
    );
    expect(curlCommand({ method: 'delete', url: 'http://localhost/x' })).toBe(`curl -i -X DELETE 'http://localhost/x'`);
    const leaky = curlCommand({ method: 'GET', url: `http://localhost/a?k=${'sk-ant-' + 'a'.repeat(30)}` });
    expect(leaky).toContain('«REDACTED»');
    expect(leaky).not.toContain('aaaaaaaaaa');
  });

  it('truncates and redacts response bodies', () => {
    const long = 'x'.repeat(PROOF_BODY_MAX + 50);
    expect(proofBody(long)).toMatch(/truncated, 550 chars/);
    const jwt = makeJwt({ sub: '1' });
    expect(proofBody(`{"token":"${jwt}"}`)).not.toContain(jwt);
    const p = buildProof({ request: { method: 'GET', url: '/a' }, status: 200, response: `t ${jwt}`, control: `c ${jwt}` });
    expect(JSON.stringify(p)).not.toContain(jwt);
  });
});

describe('active runner: proof + observations', () => {
  it('attaches a reproducible, token-free proof to every active finding', async () => {
    const seen: ActiveObservation[] = [];
    const requests = [
      { method: 'GET', path: '/api/users/1', pathParams: [{ index: 3, name: 'id' }] },
      { method: 'GET', path: '/api/admin' },
    ];
    const vulnerable = fakeApp({});
    const findings = await runActiveScan({ token: tokenA, tokenB, requests, baseUrl: base, onObserve: (o) => seen.push(o) }, vulnerable);
    const rules = findings.map((f) => f.rule).sort();
    expect(rules).toEqual(['bola-idor', 'jwt-not-verified', 'privilege-escalation']);
    for (const f of findings) {
      expect(f.proof?.request).toMatch(/^curl -i --oauth2-bearer ".*\$TOKEN.*" 'http:\/\/localhost:3000\//);
      expect(f.proof?.status).toBe(200);
      expect(f.proof?.control).toBeTruthy();
      expect(JSON.stringify(f.proof)).not.toContain(tokenA);
      expect(JSON.stringify(f.proof)).not.toContain(tokenB);
    }
    const idor = findings.find((f) => f.rule === 'bola-idor')!;
    expect(idor.proof!.request).toContain('/api/users/2');
    expect(idor.proof!.control).toMatch(/owning identity \(\$TOKEN_B\).*HTTP 200/);
    expect(seen.some((o) => o.kind === 'cross' && o.outcome === 'broken')).toBe(true);
  });
});

describe('Verifier: active findings', () => {
  it('is inconclusive without tokens in the session (never a false "fixed")', async () => {
    const r = await Verifier.verify(finding('bola-idor', '/api/users/1'), { target: '/p' });
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/--token/);
  });

  it('IDOR: still-present with proof while vulnerable; fixed once refused AND the owner still gets in', async () => {
    const f = finding('bola-idor', '/api/users/1');
    const still = await Verifier.verify(f, activeCtx(fakeApp({ verifySig: true })));
    expect(still.status).toBe('still-present');
    expect(still.proof?.request).toContain('/api/users/2');

    const fixed = await Verifier.verify(f, activeCtx(fakeApp({ verifySig: true, ownerCheck: true })));
    expect(fixed.status).toBe('fixed');
    expect(fixed.detail).toMatch(/HTTP 403.*owner still gets HTTP 200/);
  });

  it('IDOR: a refusal while the owner is ALSO failing is inconclusive (no working control)', async () => {
    const r = await Verifier.verify(finding('bola-idor', '/api/users/1'), activeCtx(fakeApp({ verifySig: true, ownerCheck: true, ownerBroken: true })));
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/owner's own request.*HTTP 500/);
  });

  it('IDOR: needs --token-b for the owner control', async () => {
    const r = await Verifier.verify(finding('bola-idor', '/api/users/1'), activeCtx(fakeApp({ ownerCheck: true }), { tokenB: undefined }));
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/--token-b/);
  });

  it('a failed request (app down) never proves fixed', async () => {
    const r = await Verifier.verify(finding('jwt-not-verified', '/api/users/1'), activeCtx(fakeApp({ down: true })));
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/not proof of a fix/);
  });

  it('JWT: fixed when the forged token gets 401 and the real token still gets 200', async () => {
    const r = await Verifier.verify(finding('jwt-not-verified', '/api/users/1'), activeCtx(fakeApp({ verifySig: true, ownerCheck: true })));
    expect(r.status).toBe('fixed');
    expect(r.detail).toMatch(/alg:none token now gets HTTP 401; your real token still gets HTTP 200/);
  });

  it('JWT: inconclusive when even the real token is rejected', async () => {
    const rejectAll: HttpFn = async () => ({ status: 401, bodyText: '' });
    const r = await Verifier.verify(finding('jwt-not-verified', '/api/users/1'), activeCtx(rejectAll));
    expect(r.status).toBe('inconclusive');
  });

  it('privilege escalation: fixed when forged admin roles are refused', async () => {
    const f = finding('privilege-escalation', '/api/admin');
    expect((await Verifier.verify(f, activeCtx(fakeApp({})))).status).toBe('still-present');
    const r = await Verifier.verify(f, activeCtx(fakeApp({ roleCheck: true })));
    expect(r.status).toBe('fixed');
    expect(r.detail).toMatch(/HTTP 403\/403/);
  });

  it('refuses to re-probe a non-loopback base URL without ownership', async () => {
    const r = await Verifier.verify(finding('bola-idor', '/api/users/1'), {
      target: '/p',
      active: { baseUrl: 'http://example.com', routes, token: tokenA, tokenB },
    });
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/--i-own-this-target example\.com/);
  });
});

describe('ownership guard (scope)', () => {
  it('allows loopback by default and refuses other hosts', () => {
    expect(assertActiveTarget('http://127.0.0.1:3000/x').hostname).toBe('127.0.0.1');
    expect(() => assertActiveTarget('https://staging.example.com')).toThrow(/--i-own-this-target staging\.example\.com/);
  });

  it('allows exactly the hosts the user declared, nothing broader', () => {
    const owned = parseOwnedHosts(['Staging.Example.com', 'api.example.com,api.example.com']);
    expect(owned).toEqual(['staging.example.com', 'api.example.com']);
    expect(assertActiveTarget('https://staging.example.com/a', owned).host).toBe('staging.example.com');
    expect(() => assertActiveTarget('https://evil.staging.example.com', owned)).toThrow(/Refusing/);
    expect(() => assertActiveTarget('https://example.com', owned)).toThrow(/Refusing/);
  });

  it('rejects ownership values that are not a bare host', () => {
    for (const bad of ['*.example.com', 'https://example.com', 'example.com:8080', 'example.com/path', 'a b']) {
      expect(() => parseOwnedHosts(bad)).toThrow(/bare host/);
    }
    expect(parseOwnedHosts(undefined)).toEqual([]);
  });

  it('refuses non-http schemes and embedded credentials even on loopback', () => {
    expect(() => assertActiveTarget('file:///etc/passwd')).toThrow(/http/);
    expect(() => assertActiveTarget('http://u:p@localhost/')).toThrow(/credentials/);
  });

  it('the adapter never leaves the declared host, even for an absolute-looking path', async () => {
    const adapter = createActiveHttpAdapter({ baseUrl: 'https://staging.example.com', ownedHosts: ['staging.example.com'], dryRun: true });
    await expect(adapter({ method: 'GET', path: '//evil.example.net/x', headers: {} })).rejects.toThrow(/Refusing/);
    await expect(adapter({ method: 'GET', path: '/ok', headers: {} })).resolves.toEqual({ status: 0, bodyText: '' });
    expect(() => createActiveHttpAdapter({ baseUrl: 'https://staging.example.com' })).toThrow(/loopback/);
  });
});

describe('unauthenticated write-route probe', () => {
  const writeRoutes: Route[] = [
    { method: 'DELETE', path: '/api/users/:id', file: 'a.js', guarded: false },
    { method: 'PATCH', path: '/api/items/{itemId}', file: 'a.js', guarded: false },
    { method: 'PUT', path: '/api/users/:id', file: 'a.js', guarded: false },
    { method: 'DELETE', path: '/api/session', file: 'a.js', guarded: false },
    { method: 'DELETE', path: '/files/*', file: 'a.js', guarded: false },
    { method: 'GET', path: '/api/users/:id', file: 'a.js', guarded: false },
  ];

  it('only plans DELETE/PATCH routes whose every parameter can point at a non-existent record', () => {
    const plan = planMutationProbes(writeRoutes, '__deployready_probe_x__');
    expect(plan.targets).toEqual([
      { method: 'DELETE', route: '/api/users/:id', path: '/api/users/__deployready_probe_x__' },
      { method: 'PATCH', route: '/api/items/{itemId}', path: '/api/items/__deployready_probe_x__' },
    ]);
    const reasons = plan.skipped.map((s) => `${s.method} ${s.path}: ${s.reason}`).join('\n');
    expect(reasons).toMatch(/PUT \/api\/users\/:id: PUT may upsert/);
    expect(reasons).toMatch(/DELETE \/api\/session: no path parameter/);
    expect(reasons).toMatch(/DELETE \/files\/\*: path is a pattern/);
  });

  const sent: { method: string; path: string; headers: Record<string, string>; body?: unknown }[] = [];
  const app = (o: { auth?: boolean; catchAll?: boolean }): HttpFn => async (req) => {
    sent.push(req);
    if (o.auth) return { status: 401, bodyText: '' };
    if (/^\/api\/users\/[^/]+$/.test(req.path) || o.catchAll) return { status: 200, bodyText: '{"ok":true}' };
    return { status: 404, bodyText: '' };
  };
  const targets = [{ method: 'DELETE', route: '/api/users/:id', path: '/api/users/__deployready_probe_x__' }];

  it('reports an anonymous 2xx with proof, sending no credentials and no body', async () => {
    sent.length = 0;
    const findings = await runMutationProbes(targets, app({}), { baseUrl: base });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.rule).toBe(MUTATION_RULE);
    expect(findings[0]!.endpoint).toBe('DELETE /api/users/:id');
    expect(findings[0]!.proof?.request).toBe(`curl -i -X DELETE 'http://localhost:3000/api/users/__deployready_probe_x__'`);
    expect(findings[0]!.proof?.control).toMatch(/HTTP 404/);
    for (const r of sent) {
      expect(r.headers).toEqual({});
      expect(r.body).toBeUndefined();
      expect(r.path).toMatch(/__deployready_probe_/);
    }
  });

  it('reports nothing for 401/403, or when a catch-all answers 2xx to everything', async () => {
    expect(await runMutationProbes(targets, app({ auth: true }))).toEqual([]);
    expect(await runMutationProbes(targets, app({ catchAll: true }))).toEqual([]);
  });

  it('Verifier: fixed only on an explicit 401/403; loopback only', async () => {
    const f = finding(MUTATION_RULE, 'DELETE /api/users/:id');
    const ctx = (h: HttpFn, baseUrl = base) => ({ target: '/p', active: { baseUrl, routes: writeRoutes, token: tokenA, http: h } });
    expect((await Verifier.verify(f, ctx(app({})))).status).toBe('still-present');
    expect((await Verifier.verify(f, ctx(app({ auth: true })))).status).toBe('fixed');
    const notFound: HttpFn = async () => ({ status: 404, bodyText: '' });
    expect((await Verifier.verify(f, ctx(notFound))).status).toBe('inconclusive');
    const down: HttpFn = async () => {
      throw new Error('ECONNRESET');
    };
    expect((await Verifier.verify(f, ctx(down))).detail).toMatch(/did not answer/);
    expect((await Verifier.verify(f, ctx(app({}), 'https://staging.example.com'))).detail).toMatch(/only re-probed on a loopback/);
  });
});

describe('proof in reports', () => {
  const proof = { request: `curl -i --oauth2-bearer "$TOKEN" 'http://localhost:3000/api/users/2'`, status: 200, response: '{"id":"2"}', control: 'Owner got HTTP 200 <b>' };
  const f = { ...finding('bola-idor', '/api/users/1'), proof };
  const report = {
    target: '/p', startedAt: 'now', finishedAt: 'now', version: '0.4.0',
    stack: { stack: 'express', language: 'javascript', evidence: [] },
    graph: { root: '/p', stack: { stack: 'express', language: 'javascript', evidence: [] }, entryPoints: [], modules: [], routes: [], fileCount: 1 },
    findings: [f], score: 70, summary: { critical: 1, warning: 0, info: 0, total: 1 },
  } as ScanReport;

  it('JSON (CI) output includes the proof', () => {
    const json = toCiJson(report, 'none') as { findings: { proof?: unknown }[] };
    expect(json.findings[0]!.proof).toEqual(proof);
  });

  it('markdown shows request, status, response and control', () => {
    const md = ExportManager.toMarkdown(report);
    expect(md).toContain(proof.request);
    expect(md).toMatch(/\*\*Status:\*\* 200/);
    expect(md).toMatch(/\*\*Control:\*\* Owner got HTTP 200/);
  });

  it('HTML shows the proof, escaped', () => {
    const html = HtmlReporter.render(report);
    expect(html).toContain('class="f-proof"');
    expect(html).toContain('Owner got HTTP 200 &lt;b&gt;');
    expect(html).not.toContain('Owner got HTTP 200 <b>');
  });

  it('terminal lines include every part of the proof', () => {
    expect(IssuePresenter.proofLines(proof)).toEqual([
      `proof: ${proof.request}`,
      '  -> HTTP 200',
      '  response: {"id":"2"}',
      '  control: Owner got HTTP 200 <b>',
    ]);
  });
});

describe('SecurityTester attaches proof to live findings', () => {
  let server: http.Server;
  let baseUrl: string;
  beforeAll((done) => {
    server = http.createServer((req, res) => {
      if (req.url === '/admin/stats') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end('{"users":2}');
      }
      res.writeHead(404);
      res.end('nope');
    });
    server.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      done();
    });
  });
  afterAll((done) => {
    server.close(() => done());
  });

  it('exposed-admin-route carries curl, status, body and the catch-all control', async () => {
    const { DynamicTester } = await import('../src/dynamic/DynamicTester');
    const res = await DynamicTester.run(baseUrl, [{ method: 'GET', path: '/admin/stats', file: 'a.js', guarded: false }]);
    const f = res.findings.find((x) => x.rule === 'exposed-admin-route');
    expect(f?.proof).toEqual({
      request: `curl -i '${baseUrl}/admin/stats'`,
      status: 200,
      response: '{"users":2}',
      control: expect.stringMatching(/random non-existent path/),
    });
  });
});

describe('rate-limit burst that is cut short', () => {
  it('is a could-not-verify note, never a "missing rate limit" finding', async () => {
    const { SecurityTester } = await import('../src/dynamic/SecurityTester');
    let calls = 0;
    const client = {
      defaults: { baseURL: 'http://localhost:3000' },
      get: jest.fn(async () => {
        calls++;
        if (calls > 3) throw new Error('ECONNRESET');
        return { status: 200, data: { ok: true }, headers: { 'content-type': 'application/json' } };
      }),
    };
    const res = await SecurityTester.run(client as never, [{ method: 'GET', path: '/api/login', guarded: false, sensitive: false, why: [] }], { aggressive: true });
    const rl = res.findings.filter((f) => f.rule === 'missing-rate-limit');
    expect(rl).toHaveLength(1);
    expect(rl[0]!.note).toBe(true);
    expect(rl[0]!.description).toMatch(/stopped after 2 of 20/);
  });
});

describe('CLI + orchestrator wiring for --i-own-this-target', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    process.exitCode = 0;
  });

  it('--i-own-this-target is repeatable and --active-url is passed through', async () => {
    const { buildProgram } = await import('../src/cli/Commands');
    const { Orchestrator } = await import('../src/core/Orchestrator');
    const report = { findings: [], summary: { critical: 0, warning: 0, info: 0, total: 0 } } as unknown as ScanReport;
    const spy = jest.spyOn(Orchestrator, 'analyze').mockResolvedValue(report);
    jest.spyOn(console, 'log').mockImplementation(() => undefined);
    await buildProgram().parseAsync([
      'node', 'deployready', 'analyze', '.', '--json',
      '--active-url', 'https://staging.example.com', '--i-own-this-target', 'staging.example.com', '--i-own-this-target', 'api.example.com',
    ]);
    expect(spy.mock.calls[0]![1]).toMatchObject({ activeUrl: 'https://staging.example.com', ownedHosts: ['staging.example.com', 'api.example.com'] });
    await buildProgram().parseAsync(['node', 'deployready', 'analyze', '.', '--json']);
    expect(spy.mock.calls[1]![1]).toMatchObject({ ownedHosts: [] });
  });

  it('a non-loopback --active-url without ownership sends nothing', async () => {
    const { Orchestrator } = await import('../src/core/Orchestrator');
    const { ConfigManager } = await import('../src/config/ConfigManager');
    const axios = (await import('axios')).default;
    jest.spyOn(ConfigManager, 'load').mockResolvedValue({ defaultPorts: [3000], ownedTargets: [] } as never);
    const req = jest.spyOn(axios, 'request');
    const graph = { routes } as never;
    const run = (Orchestrator as unknown as { runActive: (g: unknown, o: unknown) => Promise<Finding[]> }).runActive.bind(Orchestrator);
    expect(await run(graph, { token: tokenA, yes: true, activeUrl: 'https://staging.example.com' })).toEqual([]);
    expect(await run(graph, { token: tokenA, yes: true, activeUrl: 'https://staging.example.com', ownedHosts: ['*.example.com'] })).toEqual([]);
    expect(req).not.toHaveBeenCalled();
  });
});
