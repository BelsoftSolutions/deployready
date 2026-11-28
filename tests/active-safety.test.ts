/**
 * Active-scan safety (directive §7): safety levels, the unsafe-route denylist,
 * side-effect path detection, the request budget, redirect restriction, and the
 * dry-run preview. Network tests use a real loopback server.
 */
import * as http from 'http';
import type { AddressInfo } from 'net';
import {
  ActiveBudgetError,
  allowsMutationProbes,
  assertSafetyAllowed,
  matchRoutePattern,
  parseSafetyLevel,
  resolveActivePolicy,
  routeSkipReason,
  sideEffectReason,
} from '../src/active/safety';
import { planActiveRequests } from '../src/active/requestPlan';
import { planMutationProbes } from '../src/active/mutationProbe';
import { createActiveHttpAdapter } from '../src/active/httpAdapter';
import { runActiveScan, type HttpFn } from '../src/active/runner';
import { previewActivePlan } from '../src/active/dryRun';
import type { Route } from '../src/types';

const route = (method: string, path: string): Route => ({ method, path, file: 'a.js', guarded: true });

describe('safety levels', () => {
  it('parses levels, defaulting to read-only', () => {
    expect(parseSafetyLevel(undefined)).toBe('read-only');
    expect(parseSafetyLevel('Controlled-Active')).toBe('controlled-active');
    expect(() => parseSafetyLevel('yolo')).toThrow(/passive, read-only, controlled-active, stateful/);
  });

  it('resolves config + CLI (CLI wins) with aliases and a request budget', () => {
    const p = resolveActivePolicy(
      { active: { safetyLevel: 'controlled-active', maxRequests: 50, ignoredFields: ['etag'], publicRoutes: ['/api/products/*'] }, unsafeRoutes: ['/api/export*'], disposableEnvironment: true },
      { safetyLevel: 'passive' },
    );
    expect(p).toEqual({
      safetyLevel: 'passive',
      unsafeRoutes: ['/api/export*'],
      ignoredFields: ['etag'],
      publicRoutes: ['/api/products/*'],
      maxRequests: 50,
      disposableEnvironment: true,
    });
    expect(resolveActivePolicy(undefined).maxRequests).toBe(200);
  });

  it('only controlled-active and stateful allow the write-route probe', () => {
    expect(['passive', 'read-only', 'controlled-active', 'stateful'].map((l) => allowsMutationProbes(parseSafetyLevel(l)))).toEqual([false, false, true, true]);
  });

  it('refuses stateful unless the target is declared disposable AND loopback/owned', () => {
    const stateful = (disposableEnvironment: boolean) => ({ ...resolveActivePolicy(undefined, { safetyLevel: 'stateful' }), disposableEnvironment });
    expect(() => assertSafetyAllowed(stateful(false), 'http://127.0.0.1:3000', [])).toThrow(/disposableEnvironment/);
    expect(() => assertSafetyAllowed(stateful(true), 'https://staging.example.com', [])).toThrow(/stateful.*--i-own-this-target/);
    expect(() => assertSafetyAllowed(stateful(true), 'http://127.0.0.1:3000', [])).not.toThrow();
    expect(() => assertSafetyAllowed(stateful(true), 'https://staging.example.com', ['staging.example.com'])).not.toThrow();
    expect(() => assertSafetyAllowed(resolveActivePolicy(undefined), 'https://x.example.com', [])).not.toThrow(); // only stateful is gated here
  });
});

describe('GET is never assumed side-effect-free', () => {
  it('flags paths that suggest side effects', () => {
    for (const p of ['/logout', '/api/auth/sign-out', '/api/users/:id/delete', '/api/send-email', '/billing/pay', '/api/charge/:id', '/api/export', '/webhooks/stripe', '/password/reset', '/api/invoices/:id/sendReminder']) {
      expect(sideEffectReason(p)).toMatch(/side effect/);
    }
    for (const p of ['/api/users/:id/invoice', '/api/payments/:id', '/api/exports-history', '/api/settings']) {
      expect(sideEffectReason(p)).toBeNull();
    }
  });

  it('read-only (default) skips side-effect and denylisted GET routes; stateful still honours the denylist', () => {
    const routes = [route('GET', '/api/users/:id'), route('GET', '/logout'), route('GET', '/api/report'), route('GET', '/api/export')];
    const claims = { sub: 'u1' };
    const ro = planActiveRequests(routes, claims, { unsafeRoutes: ['GET /api/rep*'] });
    expect(ro.requests.map((r) => r.path)).toEqual(['/api/users/u1']);
    expect(ro.skipped.map((s) => `${s.path}: ${s.reason}`).join('\n')).toMatch(/\/logout: path suggests a side effect[\s\S]*\/api\/report: listed in unsafeRoutes/);

    const st = planActiveRequests(routes, claims, { safetyLevel: 'stateful', unsafeRoutes: ['GET /api/rep*'] });
    expect(st.requests.map((r) => r.path)).toEqual(['/api/users/u1', '/logout', '/api/export']);

    expect(planActiveRequests(routes, claims, { safetyLevel: 'passive' }).requests).toEqual([]);
  });

  it('route patterns: globs, method prefixes, template or concrete path', () => {
    expect(matchRoutePattern(['/api/admin/*'], 'GET', '/api/admin/users')).toBe('/api/admin/*');
    expect(matchRoutePattern(['DELETE /api/*'], 'GET', '/api/x')).toBeNull();
    expect(matchRoutePattern(['/api/users/u1'], 'GET', '/api/users/:id', '/api/users/u1')).toBe('/api/users/u1');
    expect(routeSkipReason('read-only', 'GET', '/api/users/:id', [])).toBeNull();
  });

  it('the write-route probe honours unsafeRoutes', () => {
    const plan = planMutationProbes([route('DELETE', '/api/users/:id'), route('PATCH', '/api/items/:id')], '__p__', { unsafeRoutes: ['DELETE /api/users/*'] });
    expect(plan.targets.map((t) => t.method)).toEqual(['PATCH']);
    expect(plan.skipped[0]!.reason).toMatch(/unsafeRoutes/);
  });
});

describe('transport: request budget and redirect restriction (real loopback server)', () => {
  let server: http.Server;
  let base = '';
  const hits: string[] = [];
  beforeAll(async () => {
    server = http.createServer((req, res) => {
      hits.push(`${req.method} ${req.url}`);
      if (req.url === '/same') return res.writeHead(302, { location: '/final' }).end();
      if (req.url === '/loop') return res.writeHead(302, { location: '/loop' }).end();
      if (req.url === '/cross') return res.writeHead(302, { location: 'http://evil.example.net/steal' }).end();
      if (req.url === '/cross-port') return res.writeHead(302, { location: 'http://127.0.0.1:1/x' }).end();
      if (req.url === '/final') return res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
      res.writeHead(404).end('{}');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));
  beforeEach(() => {
    hits.length = 0;
  });

  it('follows a same-host GET redirect after re-checking scope', async () => {
    const http_ = createActiveHttpAdapter({ baseUrl: base });
    const r = await http_({ method: 'GET', path: '/same', headers: {} });
    expect(r.status).toBe(200);
    expect(r.url).toBe(`${base}/final`);
    expect(hits).toEqual(['GET /same', 'GET /final']);
  });

  it('never follows a cross-host (or cross-port) redirect: the 3xx is the answer', async () => {
    const http_ = createActiveHttpAdapter({ baseUrl: base });
    expect((await http_({ method: 'GET', path: '/cross', headers: {} })).status).toBe(302);
    expect((await http_({ method: 'GET', path: '/cross-port', headers: {} })).status).toBe(302);
    expect(hits).toEqual(['GET /cross', 'GET /cross-port']);
  });

  it('caps redirect hops and never follows redirects for non-GET methods', async () => {
    const http_ = createActiveHttpAdapter({ baseUrl: base });
    expect((await http_({ method: 'GET', path: '/loop', headers: {} })).status).toBe(302);
    expect(hits).toHaveLength(4);
    hits.length = 0;
    expect((await http_({ method: 'DELETE', path: '/same', headers: {} })).status).toBe(302);
    expect(hits).toEqual(['DELETE /same']);
  });

  it('enforces a hard request budget (redirect hops count)', async () => {
    const http_ = createActiveHttpAdapter({ baseUrl: base, maxRequests: 3 });
    await http_({ method: 'GET', path: '/same', headers: {} });
    await http_({ method: 'GET', path: '/final', headers: {} });
    await expect(http_({ method: 'GET', path: '/final', headers: {} })).rejects.toBeInstanceOf(ActiveBudgetError);
    expect(hits).toHaveLength(3);
  });

  it('the runner keeps its findings when the transport budget runs out', async () => {
    let n = 0;
    const app: HttpFn = async (req) => {
      if (++n > 3) throw new ActiveBudgetError(3);
      return req.headers.Authorization ? { status: 200, bodyText: '{}' } : { status: 401, bodyText: '' };
    };
    const tok = `${Buffer.from('{"alg":"HS256"}').toString('base64url')}.${Buffer.from('{"sub":"1"}').toString('base64url')}.sig`;
    const findings = await runActiveScan({ token: tok, requests: [{ method: 'GET', path: '/a' }, { method: 'GET', path: '/b' }] }, app);
    expect(findings.map((f) => f.rule)).toEqual(['jwt-not-verified']);
  });
});

describe('dry run', () => {
  it('lists every planned request (with $TOKEN placeholders) and the budget, sending nothing', () => {
    const requests = planActiveRequests([route('GET', '/api/users/:id/invoice'), route('GET', '/logout')], { sub: 'alice' });
    const dry = previewActivePlan({
      baseUrl: 'http://127.0.0.1:3000',
      safetyLevel: 'read-only',
      requests: requests.requests,
      tokenBClaims: { sub: 'bob' },
      skipped: requests.skipped,
      maxRequests: 200,
    });
    const text = dry.lines.join('\n');
    expect(text).toMatch(/dry run — safety level "read-only"\. Nothing below is sent/);
    expect(text).toMatch(/GET http:\/\/127\.0\.0\.1:3000\/api\/users\/alice\/invoice {2}as \$TOKEN \(baseline\)/);
    expect(text).toMatch(/\/api\/users\/bob\/invoice {2}as \$TOKEN \(path param "id" swapped/);
    expect(text).toMatch(/\/api\/users\/bob\/invoice {2}as \$TOKEN_B ×2 \(owner baselines\)/);
    expect(text).toMatch(/\/logout: path suggests a side effect/);
    expect(text).toMatch(/At most 9 request\(s\)/);
    expect(dry.upperBound).toBe(9);
    expect(text).not.toMatch(/eyJ/);
  });
});
