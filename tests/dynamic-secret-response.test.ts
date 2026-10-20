import * as http from 'http';
import type { AddressInfo } from 'net';
import { DynamicTester } from '../src/dynamic/DynamicTester';
import type { Route } from '../src/types';

const FAKE_KEY = 'AKIAIOSFODNN7EXAMPLE';

let server: http.Server;
let baseUrl: string;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/config') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ config: { key: FAKE_KEY } }));
    }
    if (url === '/nested') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ items: [{ id: 1, note: `prefix ${FAKE_KEY} suffix` }] }));
    }
    if (url === '/clean') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ config: { region: 'eu-west-1', count: 3 } }));
    }
    if (url === '/text') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end(`your key is ${FAKE_KEY}`);
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

const route = (path: string): Route => ({ method: 'GET', path, file: 'api.js', guarded: false });

describe('secret-in-response on JSON bodies', () => {
  it('detects a secret inside a JSON response without leaking it into the finding', async () => {
    const results = await DynamicTester.run(baseUrl, [route('/config')]);
    const f = results.findings.find((x) => x.rule === 'secret-in-response' && x.endpoint === '/config');
    expect(f).toBeDefined();
    expect(f!.severity).toBe('critical');
    expect(JSON.stringify(results)).not.toContain(FAKE_KEY);
  }, 20000);

  it('detects a secret embedded in a nested JSON string value', async () => {
    const results = await DynamicTester.run(baseUrl, [route('/nested')]);
    const f = results.findings.find((x) => x.rule === 'secret-in-response' && x.endpoint === '/nested');
    expect(f?.severity).toBe('critical');
    expect(JSON.stringify(results)).not.toContain(FAKE_KEY);
  }, 20000);

  it('does not report JSON without a secret', async () => {
    const results = await DynamicTester.run(baseUrl, [route('/clean')]);
    expect(results.findings.some((x) => x.rule === 'secret-in-response' && x.endpoint === '/clean')).toBe(false);
  }, 20000);

  it('still detects a secret in a plain-text body', async () => {
    const results = await DynamicTester.run(baseUrl, [route('/text')]);
    const f = results.findings.find((x) => x.rule === 'secret-in-response' && x.endpoint === '/text');
    expect(f?.severity).toBe('critical');
    expect(JSON.stringify(results)).not.toContain(FAKE_KEY);
  }, 20000);
});
