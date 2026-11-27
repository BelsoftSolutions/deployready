import * as http from 'http';
import type { AddressInfo } from 'net';
import { DynamicTester } from '../src/dynamic/DynamicTester';
import { activeContextFromEnv, tokensFromEnv } from '../src/core/Verifier';
import type { Route } from '../src/types';

let server: http.Server;
let baseUrl: string;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = req.url ?? '/';
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('X-Powered-By', 'Express 4.18.2');
    if (url === '/slow') {
      return setTimeout(() => { res.writeHead(200); res.end('slow'); }, 1100);
    }
    if (url === '/boom') {
      res.writeHead(500);
      return res.end('Error: boom\n    at handler (server.js:10:5)');
    }
    if (url === '/leak') { res.writeHead(200); return res.end('key AKIAIOSFODNN7EXAMPLE'); }
    if (['/admin', '/guarded', '/ok'].includes(url)) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, url }));
    }
    res.writeHead(404);
    res.end('not found');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

const route = (path: string, guarded = false): Route => ({ method: 'GET', path, file: 'a.js', guarded });

describe('every dynamic finding carries proof', () => {
  it('attaches redacted proof to each finding type the testers produce', async () => {
    const res = await DynamicTester.run(baseUrl, [route('/slow'), route('/boom'), route('/leak'), route('/admin'), route('/guarded', true), route('/ok')]);
    const real = res.findings.filter((f) => !f.note);
    const rules = new Set(real.map((f) => f.rule));
    for (const r of ['slow-endpoint', 'missing-cache-headers', 'version-banner', 'stack-trace-leak', 'secret-in-response', 'cors-wildcard-live', 'missing-security-headers', 'auth-bypass', 'exposed-admin-route']) {
      expect(rules).toContain(r);
    }
    for (const f of real) {
      expect({ rule: f.rule, proof: Boolean(f.proof?.request) }).toEqual({ rule: f.rule, proof: true });
    }
    expect(JSON.stringify(res)).not.toContain('AKIAIOSFODNN7EXAMPLE');
  }, 30000);
});

describe('env tokens', () => {
  it('reads tokens only from env and requires a base URL', () => {
    expect(tokensFromEnv({})).toBeUndefined();
    expect(tokensFromEnv({ DEPLOYREADY_TOKEN: ' a ', DEPLOYREADY_TOKEN_B: 'b' })).toEqual({ token: 'a', tokenB: 'b' });
    expect(activeContextFromEnv(undefined, [], { DEPLOYREADY_TOKEN: 'a' })).toBeUndefined();
    expect(activeContextFromEnv('http://127.0.0.1:1', [], { DEPLOYREADY_TOKEN: 'a' })).toMatchObject({ token: 'a', baseUrl: 'http://127.0.0.1:1' });
    expect(activeContextFromEnv('http://127.0.0.1:1', [], {})).toBeUndefined();
  });
});
