import * as http from 'http';
import type { AddressInfo } from 'net';
import { DynamicTester } from '../src/dynamic/DynamicTester';
import type { Route } from '../src/types';

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

async function withServer<T>(handler: Handler, fn: (baseUrl: string) => Promise<T>): Promise<T> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    return await fn(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

const notFound = (res: http.ServerResponse) => {
  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
};

const INDEX_HTML = '<!doctype html><html><body><div id="root"></div><script src="/app.js"></script></body></html>';
const spa = (res: http.ServerResponse) => {
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(INDEX_HTML);
};

const rulesAt = (findings: { rule: string; endpoint?: string }[], rule: string) =>
  findings.filter((f) => f.rule === rule).map((f) => f.endpoint);

const adminRoutes = (...paths: string[]): Route[] =>
  paths.map((path) => ({ method: 'GET', path, file: 'a.js', guarded: false }));

describe('exposed-admin-route false positives', () => {
  it('keeps the true positive: a real 200 /admin that differs from the 404 page', async () => {
    const r = await withServer((req, res) => {
      if (req.url === '/admin') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end('{"users":[{"id":1}],"admin":true}');
      }
      notFound(res);
    }, (url) => DynamicTester.run(url, adminRoutes('/admin')));
    expect(rulesAt(r.findings, 'exposed-admin-route')).toEqual(['/admin']);
  }, 20000);

  it('keeps the true positive for a real HTML admin page too', async () => {
    const r = await withServer((req, res) => {
      if (req.url === '/admin') {
        res.writeHead(200, { 'content-type': 'text/html' });
        return res.end('<h1>Admin console</h1>');
      }
      notFound(res);
    }, (url) => DynamicTester.run(url, adminRoutes('/admin')));
    expect(rulesAt(r.findings, 'exposed-admin-route')).toEqual(['/admin']);
  }, 20000);

  it('does not report a 302 redirect to a login page', async () => {
    const r = await withServer((req, res) => {
      if (req.url === '/admin' || req.url === '/debug') {
        res.writeHead(302, { location: '/login' });
        return res.end();
      }
      notFound(res);
    }, (url) => DynamicTester.run(url, adminRoutes('/admin', '/debug')));
    expect(rulesAt(r.findings, 'exposed-admin-route')).toEqual([]);
  }, 20000);

  it('does not report 401, 403 or 5xx responses', async () => {
    const r = await withServer((req, res) => {
      const code: Record<string, number> = { '/admin': 401, '/api/admin': 403, '/debug': 500 };
      const c = code[req.url ?? ''];
      if (c) {
        res.writeHead(c);
        return res.end('nope');
      }
      notFound(res);
    }, (url) => DynamicTester.run(url, adminRoutes('/admin', '/api/admin', '/debug')));
    expect(rulesAt(r.findings, 'exposed-admin-route')).toEqual([]);
  }, 20000);

  it('does not report an SPA that serves the same index.html for every path', async () => {
    const routes: Route[] = [{ method: 'GET', path: '/dashboard', file: 'a.js', guarded: true }];
    const r = await withServer((_req, res) => spa(res), (url) => DynamicTester.run(url, routes));
    expect(rulesAt(r.findings, 'exposed-admin-route')).toEqual([]);
  }, 20000);

  it('still reports a path genuinely served with different content behind a catch-all', async () => {
    const r = await withServer((req, res) => {
      if (req.url === '/admin') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        return res.end('DATABASE_URL=postgres://db.internal/app\nMODE=prod\n');
      }
      spa(res);
    }, (url) => DynamicTester.run(url, adminRoutes('/admin')));
    expect(rulesAt(r.findings, 'exposed-admin-route')).toEqual(['/admin']);
  }, 20000);

  it('treats equal status and content-length as the catch-all even if bytes differ', async () => {
    const r = await withServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<html><body>build ${Math.floor(Math.random() * 10)}</body></html>`);
    }, (url) => DynamicTester.run(url, adminRoutes('/admin')));
    expect(rulesAt(r.findings, 'exposed-admin-route')).toEqual([]);
  }, 20000);
});

describe('auth-bypass with the catch-all baseline', () => {
  const guarded: Route[] = [{ method: 'GET', path: '/dashboard', file: 'a.js', guarded: true }];

  it('keeps the true positive: a guarded route that really answers 200 anonymously', async () => {
    const r = await withServer((req, res) => {
      if (req.url === '/dashboard') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end('{"account":{"id":1}}');
      }
      notFound(res);
    }, (url) => DynamicTester.run(url, guarded));
    expect(rulesAt(r.findings, 'auth-bypass')).toEqual(['/dashboard']);
  }, 20000);

  it('does not report a guarded route that returns 401, 403 or a redirect', async () => {
    const routes: Route[] = [
      { method: 'GET', path: '/a', file: 'a.js', guarded: true },
      { method: 'GET', path: '/b', file: 'a.js', guarded: true },
      { method: 'GET', path: '/c', file: 'a.js', guarded: true },
    ];
    const r = await withServer((req, res) => {
      if (req.url === '/a') {
        res.writeHead(401);
        return res.end('no');
      }
      if (req.url === '/b') {
        res.writeHead(403);
        return res.end('no');
      }
      if (req.url === '/c') {
        res.writeHead(302, { location: '/login' });
        return res.end();
      }
      notFound(res);
    }, (url) => DynamicTester.run(url, routes));
    expect(rulesAt(r.findings, 'auth-bypass')).toEqual([]);
  }, 20000);

  it('does not report guarded paths on an SPA that serves index.html for every path', async () => {
    const r = await withServer((_req, res) => spa(res), (url) => DynamicTester.run(url, guarded));
    expect(rulesAt(r.findings, 'auth-bypass')).toEqual([]);
    expect(rulesAt(r.findings, 'exposed-admin-route')).toEqual([]);
  }, 20000);

  it('still reports a guarded route that serves distinct data behind a catch-all', async () => {
    const r = await withServer((req, res) => {
      if (req.url === '/dashboard') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end('{"account":{"id":1,"email":"a@b.c"}}');
      }
      spa(res);
    }, (url) => DynamicTester.run(url, guarded));
    expect(rulesAt(r.findings, 'auth-bypass')).toEqual(['/dashboard']);
  }, 20000);
});
