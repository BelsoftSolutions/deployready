import * as http from 'http';
import type { AddressInfo } from 'net';
import { buildUrl, createActiveHttpAdapter } from '../src/active/httpAdapter';

describe('active/httpAdapter — buildUrl', () => {
  it('joins base + path and appends query params', () => {
    expect(buildUrl('http://localhost:3000', '/users/1')).toBe('http://localhost:3000/users/1');
    expect(buildUrl('http://localhost:3000', '/api', { org_id: 'B', n: 2 })).toBe(
      'http://localhost:3000/api?org_id=B&n=2',
    );
  });
});

describe('active/httpAdapter — safety', () => {
  it('refuses a non-loopback target (SSRF guard / scope)', () => {
    expect(() => createActiveHttpAdapter({ baseUrl: 'http://example.com' })).toThrow(/loopback|non-loopback/i);
  });
});

describe('active/httpAdapter — live (loopback server)', () => {
  let server: http.Server;
  let baseUrl: string;
  let lastAuth: string | undefined;
  let hits = 0;

  beforeAll((done) => {
    server = http.createServer((req, res) => {
      hits++;
      lastAuth = req.headers.authorization;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    server.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      done();
    });
  });

  afterAll((done) => {
    server.close(() => done());
  });

  it('sends the request with the Authorization header and returns status + body', async () => {
    const adapter = createActiveHttpAdapter({ baseUrl });
    const res = await adapter({ method: 'GET', path: '/users/1', headers: { Authorization: 'Bearer XYZ' } });
    expect(res.status).toBe(200);
    expect(res.bodyText).toContain('/users/1');
    expect(lastAuth).toBe('Bearer XYZ');
  });

  it('dry-run sends nothing and returns a non-2xx sentinel', async () => {
    const before = hits;
    const adapter = createActiveHttpAdapter({ baseUrl, dryRun: true });
    const res = await adapter({ method: 'GET', path: '/x', headers: {} });
    expect(hits).toBe(before); // no request made
    expect(res.status >= 200 && res.status < 300).toBe(false);
  });
});
