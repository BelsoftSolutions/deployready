import * as http from 'http';
import type { AddressInfo } from 'net';
import { DynamicTester } from '../src/dynamic/DynamicTester';
import { LocalhostDetector } from '../src/dynamic/LocalhostDetector';
import { EndpointMapper } from '../src/dynamic/EndpointMapper';
import { assertLoopback } from '../src/dynamic/httpClient';
import { ScoreCalculator } from '../src/analysis/ScoreCalculator';
import { shouldFail } from '../src/core/CiGate';
import type { Route } from '../src/types';

let server: http.Server;
let baseUrl: string;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = req.url ?? '/';
    // Vulnerable on purpose: wildcard CORS + version banner on everything.
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('X-Powered-By', 'Express 4.18.2');

    if (url.startsWith('/leak')) {
      res.writeHead(200);
      return res.end('your key is AKIAIOSFODNN7EXAMPLE');
    }
    if (url.startsWith('/boom')) {
      res.writeHead(500);
      return res.end('Error: boom\n    at handler (server.js:10:5)');
    }
    // A normal app: known routes answer 200, anything else is a 404 (so the
    // catch-all baseline probe does not mask the planted open routes).
    if (['/', '/health', '/profile', '/admin'].includes(url)) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, path: url }));
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe('assertLoopback', () => {
  it('accepts loopback hosts and rejects remote ones', () => {
    expect(() => assertLoopback('http://localhost:3000')).not.toThrow();
    expect(() => assertLoopback('http://127.0.0.1:3000')).not.toThrow();
    expect(() => assertLoopback('http://example.com')).toThrow(/loopback/);
    expect(() => assertLoopback('http://169.254.169.254')).toThrow(/loopback/); // cloud metadata
  });
});

describe('EndpointMapper', () => {
  it('targets only discovered routes: no common paths, no invented ids, admin-like by evidence', () => {
    const routes: Route[] = [
      { method: 'GET', path: '/users/:id', file: 'a.js', guarded: false },
      { method: 'GET', path: '/admin', file: 'a.js', guarded: false },
    ];
    const { targets, skipped } = EndpointMapper.plan(routes);
    expect(targets.map((t) => t.path)).toEqual(['/admin']); // no '/', '/health', '/users/1'
    expect(targets[0]!.sensitive).toBe(true);
    expect(skipped.map((s) => s.path)).toEqual(['/users/:id']);
  });
});

describe('LocalhostDetector', () => {
  it('finds the running server and ignores closed ports', async () => {
    const found = await LocalhostDetector.find([port]);
    expect(found?.port).toBe(port);
    const none = await LocalhostDetector.find([1]); // port 1: not listening
    expect(none).toBeNull();
  });
});

describe('DynamicTester (integration against a live local server)', () => {
  it('detects the planted runtime issues', async () => {
    const routes: Route[] = [
      { method: 'GET', path: '/profile', file: 'auth.js', guarded: true }, // auth-bypass (2xx while guarded)
      { method: 'GET', path: '/leak', file: 'api.js', guarded: false }, // secret in response
      { method: 'GET', path: '/boom', file: 'api.js', guarded: false }, // stack trace leak
      { method: 'GET', path: '/admin', file: 'api.js', guarded: false }, // admin-like by its own path
    ];
    const results = await DynamicTester.run(baseUrl, routes);
    const rules = new Set(results.findings.map((f) => f.rule));

    expect(rules.has('auth-bypass')).toBe(true);
    expect(rules.has('secret-in-response')).toBe(true);
    expect(rules.has('stack-trace-leak')).toBe(true);
    expect(rules.has('cors-wildcard-live')).toBe(true);
    expect(rules.has('version-banner')).toBe(true);
    expect(rules.has('exposed-admin-route')).toBe(true); // the discovered /admin returns 200

    // CORS is server-wide → reported once, not per endpoint.
    expect(results.findings.filter((f) => f.rule === 'cors-wildcard-live')).toHaveLength(1);
  }, 20000);

  it('refuses to test a non-loopback target', async () => {
    await expect(DynamicTester.run('http://example.com', [])).rejects.toThrow(/loopback/);
  });
});

describe('rate-limit probe accuracy', () => {
  const INDEX = '<!doctype html><html><body><form action="/login" method="post"></form></body></html>';

  async function probe(
    handler: (req: http.IncomingMessage, res: http.ServerResponse, hits: Map<string, number>) => void,
    routes: Route[],
    aggressive = true,
  ) {
    const hits = new Map<string, number>();
    const srv = http.createServer((req, res) => {
      const url = req.url ?? '/';
      hits.set(url, (hits.get(url) ?? 0) + 1);
      handler(req, res, hits);
    });
    await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
    try {
      const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
      const results = await DynamicTester.run(base, routes, { aggressive });
      return { findings: results.findings.filter((f) => f.rule === 'missing-rate-limit'), hits };
    } finally {
      await new Promise<void>((resolve) => srv.close(() => resolve()));
    }
  }

  const route = (path: string): Route => ({ method: 'GET', path, file: 'a.js', guarded: false });
  const json = (res: http.ServerResponse, status = 200) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: status === 200 }));
  };
  const notFound = (res: http.ServerResponse) => {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  };

  it('does not burst or report a plain HTML login page', async () => {
    const { findings, hits } = await probe((req, res) => {
      if (req.url === '/login') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(INDEX);
      }
      notFound(res);
    }, [route('/login')]);
    expect(findings.filter((f) => f.severity !== 'info')).toHaveLength(0);
    expect(findings.map((f) => f.endpoint)).toEqual(['/login']);
    expect(hits.get('/login') ?? 0).toBeLessThan(10);
  }, 20000);

  it('reports a JSON auth endpoint without a limiter as a low-confidence warning', async () => {
    const { findings } = await probe((req, res) => (req.url === '/api/auth/session' ? json(res) : notFound(res)), [
      route('/api/auth/session'),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.endpoint).toBe('/api/auth/session');
    expect(findings[0]!.severity).toBe('warning');
    expect(findings[0]!.description).toMatch(/low confidence/i);
    expect(findings[0]!.description).toMatch(/GET requests only/);
    expect(findings[0]!.description).toMatch(/login POST route itself is not probed/);
  }, 20000);

  it('skips an HTML login page but still bursts a later JSON auth endpoint', async () => {
    const { findings, hits } = await probe(
      (req, res) => {
        if (req.url === '/login') {
          res.writeHead(200, { 'content-type': 'text/html' });
          return res.end(INDEX);
        }
        if (req.url === '/api/auth/session') return json(res);
        notFound(res);
      },
      [route('/login'), route('/api/auth/session')],
    );
    expect(findings.filter((f) => f.severity !== 'info').map((f) => f.endpoint)).toEqual(['/api/auth/session']);
    expect(findings.filter((f) => f.severity === 'info').map((f) => f.endpoint)).toEqual(['/login']);
    expect(hits.get('/login') ?? 0).toBeLessThan(10);
  }, 20000);

  it('reports nothing when the auth endpoint returns 429 after a few requests', async () => {
    const { findings } = await probe((req, res, hits) => {
      if (req.url !== '/api/auth/session') return notFound(res);
      json(res, (hits.get(req.url) ?? 0) > 5 ? 429 : 200);
    }, [route('/api/auth/session')]);
    expect(findings).toHaveLength(0);
  }, 20000);

  it('reports nothing when no route looks like a login/auth endpoint', async () => {
    const { findings } = await probe((req, res) => (req.url === '/profile' ? json(res) : notFound(res)), [
      route('/profile'),
    ]);
    expect(findings).toHaveLength(0);
  }, 20000);

  const postRoute = (path: string): Route => ({ method: 'POST', path, file: 'a.js', guarded: false });

  it('notes (info, never a missing-limiter claim) a POST-only login route it cannot probe', async () => {
    const { findings, hits } = await probe(
      (req, res) => (req.url === '/api/login' && req.method === 'POST' ? json(res, 401) : notFound(res)),
      [postRoute('/api/login')],
    );
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.severity).toBe('info');
    expect(f.endpoint).toBe('/api/login');
    expect(f.title).toBe('Rate limiting on /api/login could not be verified');
    expect(f.description).toMatch(/only sends GET requests/);
    expect(f.description).toMatch(/not tested/);
    expect(f.description).toMatch(/does not mean a limiter is missing/);
    expect(f.recommendation).toMatch(/Check that a rate limiter/);
    expect(hits.get('/api/login') ?? 0).toBe(0); // GET-only: nothing was sent
  }, 20000);

  it('emits one note per unprobeable auth path even if listed under several methods', async () => {
    const { findings } = await probe(
      (req, res) => (req.url === '/api/login' ? json(res, 401) : notFound(res)),
      [postRoute('/api/login'), { ...postRoute('/api/login'), method: 'PUT' }, postRoute('/api/auth/token')],
    );
    expect(findings.map((f) => f.endpoint).sort()).toEqual(['/api/auth/token', '/api/login']);
  }, 20000);

  it('stays silent about a POST-only login on a non-aggressive run', async () => {
    const { findings } = await probe((req, res) => notFound(res), [postRoute('/api/login')], false);
    expect(findings).toHaveLength(0);
  }, 20000);

  it('the unverifiable note is returned but has zero score impact and trips no gate, including info', async () => {
    const { findings } = await probe((req, res) => notFound(res), [postRoute('/api/login')]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.note).toBe(true);
    expect(findings[0]!.rule).toBe('missing-rate-limit');
    const clean = ScoreCalculator.summarize([]);
    const withNote = ScoreCalculator.summarize(findings);
    expect(withNote).toMatchObject({ critical: 0, warning: 0, info: 0, total: 0, notes: 1 });
    expect(ScoreCalculator.calculate(withNote)).toBe(ScoreCalculator.calculate(clean));
    for (const level of ['critical', 'warning', 'info'] as const) {
      expect(shouldFail(withNote, level)).toBe(false);
    }
  }, 20000);

  it('does not burst on a non-aggressive run', async () => {
    const { findings, hits } = await probe(
      (req, res) => (req.url === '/api/auth/session' ? json(res) : notFound(res)),
      [route('/api/auth/session')],
      false,
    );
    expect(findings).toHaveLength(0);
    expect(hits.get('/api/auth/session') ?? 0).toBeLessThan(5);
  }, 20000);
});
