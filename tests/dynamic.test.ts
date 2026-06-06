import * as http from 'http';
import type { AddressInfo } from 'net';
import { DynamicTester } from '../src/dynamic/DynamicTester';
import { LocalhostDetector } from '../src/dynamic/LocalhostDetector';
import { EndpointMapper } from '../src/dynamic/EndpointMapper';
import { assertLoopback } from '../src/dynamic/httpClient';
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
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
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
  it('includes sensitive + common paths and composes route params', () => {
    const routes: Route[] = [{ method: 'GET', path: '/users/:id', file: 'a.js', guarded: false }];
    const targets = EndpointMapper.build(routes);
    const paths = targets.map((t) => t.path);
    expect(paths).toContain('/users/1'); // :id -> 1
    expect(paths).toContain('/admin'); // sensitive
    expect(paths).toContain('/'); // common
    expect(targets.find((t) => t.path === '/admin')?.sensitive).toBe(true);
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
    ];
    const results = await DynamicTester.run(baseUrl, routes);
    const rules = new Set(results.findings.map((f) => f.rule));

    expect(rules.has('auth-bypass')).toBe(true);
    expect(rules.has('secret-in-response')).toBe(true);
    expect(rules.has('stack-trace-leak')).toBe(true);
    expect(rules.has('cors-wildcard-live')).toBe(true);
    expect(rules.has('version-banner')).toBe(true);
    expect(rules.has('exposed-admin-route')).toBe(true); // /admin etc. return 200

    // CORS is server-wide → reported once, not per endpoint.
    expect(results.findings.filter((f) => f.rule === 'cors-wildcard-live')).toHaveLength(1);
  }, 20000);

  it('refuses to test a non-loopback target', async () => {
    await expect(DynamicTester.run('http://example.com', [])).rejects.toThrow(/loopback/);
  });
});
