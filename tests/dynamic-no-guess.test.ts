import * as http from 'http';
import * as net from 'net';
import type { AddressInfo } from 'net';
import { DynamicTester } from '../src/dynamic/DynamicTester';
import { LocalhostDetector } from '../src/dynamic/LocalhostDetector';
import { setVerbose } from '../src/utils/logger';
import type { Route } from '../src/types';

interface Recorder {
  baseUrl: string;
  port: number;
  requests: string[];
  connections: number;
  close: () => Promise<void>;
}

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

async function recorder(handler: Handler): Promise<Recorder> {
  const rec = { requests: [] as string[], connections: 0 } as Recorder;
  const server = http.createServer((req, res) => {
    rec.requests.push(`${req.method} ${req.url}`);
    handler(req, res);
  });
  server.on('connection', () => rec.connections++);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  rec.port = (server.address() as AddressInfo).port;
  rec.baseUrl = `http://127.0.0.1:${rec.port}`;
  rec.close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return rec;
}

async function withApp<T>(handler: Handler, fn: (rec: Recorder) => Promise<T>): Promise<T> {
  const rec = await recorder(handler);
  try {
    return await fn(rec);
  } finally {
    await rec.close();
  }
}

const json = (res: http.ServerResponse, status = 200, body: unknown = { ok: true }) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};
const notFound = (res: http.ServerResponse) => {
  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
};
const route = (method: string, path: string, guarded = false): Route => ({ method, path, file: 'src/app.js', line: 3, guarded });
const CONTROL = /^GET \/__deployready_probe_[0-9a-f]{12}$/;

describe('dynamic scan sends nothing it has no evidence for', () => {
  it('run(url, []) sends zero requests and returns the dynamic-skipped note', async () => {
    await withApp(
      (_req, res) => json(res),
      async (rec) => {
        const r = await DynamicTester.run(rec.baseUrl, [], { aggressive: true });
        expect(rec.requests).toEqual([]);
        expect(r.endpoints).toEqual([]);
        expect(r.probed).toEqual([]);
        expect(r.findings).toHaveLength(1);
        const note = r.findings[0]!;
        expect(note).toMatchObject({ rule: 'dynamic-skipped', severity: 'info', note: true });
        expect(note.title).toBe('No routes discovered; dynamic checks skipped');
        expect(note.description).toMatch(/does not guess routes/);
        expect(note.description).toMatch(/nothing was requested/);
      },
    );
  });

  it('routes that exist but cannot be probed: zero requests, reasons grouped in the note', async () => {
    await withApp(
      (_req, res) => json(res),
      async (rec) => {
        const routes = [route('POST', '/login'), route('GET', '/users/:id'), route('GET', '/orgs/:id')];
        const r = await DynamicTester.run(rec.baseUrl, routes);
        expect(rec.requests).toEqual([]);
        const note = r.findings.find((f) => f.rule === 'dynamic-skipped')!;
        expect(note.title).toBe('3 routes discovered but none could be probed; dynamic checks skipped');
        expect(note.description).toMatch(/1 x non-GET route: the scanner never mutates data/);
        expect(note.description).toMatch(/2 x needs a value for path parameter/);
        expect(note.note).toBe(true);
        expect(r.skipped).toHaveLength(3);
      },
    );
  });

  it('requests only the discovered GET routes; the skipped ones get one note, nothing is guessed', async () => {
    await withApp(
      (req, res) => (req.url === '/ping' ? json(res) : notFound(res)),
      async (rec) => {
        const routes = [route('GET', '/ping'), route('GET', '/users/:id'), route('POST', '/things')];
        const r = await DynamicTester.run(rec.baseUrl, routes);
        expect(new Set(rec.requests)).toEqual(new Set(['GET /ping']));
        expect(rec.requests.length).toBeLessThanOrEqual(3);
        expect(r.probed.map((p) => `${p.method} ${p.path}`)).toEqual(['GET /ping']);
        expect(r.probed[0]!.why).toEqual(['discovered at src/app.js:3', 'unguarded in code']);
        const notes = r.findings.filter((f) => f.rule === 'dynamic-routes-skipped');
        expect(notes).toHaveLength(1);
        expect(notes[0]).toMatchObject({ severity: 'info', note: true });
        expect(notes[0]!.description).toMatch(/GET \/users\/:id/);
        expect(notes[0]!.description).toMatch(/POST \/things/);
      },
    );
  });

  it('lists at most 10 skipped routes in the note', async () => {
    await withApp(
      (_req, res) => json(res),
      async (rec) => {
        const routes = [route('GET', '/ok'), ...Array.from({ length: 14 }, (_, i) => route('POST', `/p${i}`))];
        const r = await DynamicTester.run(rec.baseUrl, routes);
        const desc = r.findings.find((f) => f.rule === 'dynamic-routes-skipped')!.description;
        expect(desc).toMatch(/POST \/p9 /);
        expect(desc).not.toMatch(/POST \/p10 /);
        expect(desc).toMatch(/and 4 more/);
      },
    );
  });

  it('an app whose admin area has another name is never asked for /admin or any other guess', async () => {
    await withApp(
      (req, res) => (req.url === '/backoffice/stats' ? json(res, 200, { users: 3 }) : notFound(res)),
      async (rec) => {
        const r = await DynamicTester.run(rec.baseUrl, [route('GET', '/backoffice/stats')]);
        const nonControl = rec.requests.filter((q) => !CONTROL.test(q));
        expect(nonControl.length).toBeGreaterThan(0);
        expect(nonControl.every((q) => q === 'GET /backoffice/stats')).toBe(true);
        expect(r.findings.find((f) => f.rule === 'exposed-admin-route')?.endpoint).toBe('/backoffice/stats');
      },
    );
  });
});

describe('catch-all baseline is lazy', () => {
  it('sends no control request when nothing would be reported', async () => {
    await withApp(
      (req, res) => (req.url === '/me' ? json(res, 401) : json(res)),
      async (rec) => {
        await DynamicTester.run(rec.baseUrl, [route('GET', '/me', true), route('GET', '/public')]);
        expect(rec.requests.some((q) => CONTROL.test(q))).toBe(false);
        expect(new Set(rec.requests)).toEqual(new Set(['GET /me', 'GET /public']));
      },
    );
  });

  it('sends no control request for a 2xx on an unguarded, non-admin route', async () => {
    await withApp(
      (_req, res) => json(res),
      async (rec) => {
        await DynamicTester.run(rec.baseUrl, [route('GET', '/anything')]);
        expect(rec.requests.filter((q) => CONTROL.test(q))).toEqual([]);
      },
    );
  });

  it('sends exactly one control request when guarded/admin routes return 2xx, however many there are', async () => {
    await withApp(
      (req, res) => (req.url?.startsWith('/__deployready_probe_') ? notFound(res) : json(res, 200, { p: req.url })),
      async (rec) => {
        const r = await DynamicTester.run(rec.baseUrl, [route('GET', '/a', true), route('GET', '/b', true), route('GET', '/staff/list')]);
        expect(rec.requests.filter((q) => CONTROL.test(q))).toHaveLength(1);
        expect(r.findings.filter((f) => f.rule === 'auth-bypass').map((f) => f.endpoint)).toEqual(['/a', '/b']);
      },
    );
  });
});

describe('LocalhostDetector', () => {
  it('detects a listening port with a TCP connect and sends zero HTTP requests', async () => {
    await withApp(
      (_req, res) => json(res),
      async (rec) => {
        const found = await LocalhostDetector.find([rec.port]);
        expect(found?.port).toBe(rec.port);
        const all = await LocalhostDetector.findAll([rec.port]);
        expect(all.map((a) => a.port)).toEqual([rec.port]);
        await new Promise((r) => setTimeout(r, 100));
        expect(rec.connections).toBeGreaterThan(0);
        expect(rec.requests).toEqual([]);
      },
    );
  });

  it('reports a non-HTTP TCP listener too (liveness is a connect only)', async () => {
    const srv = net.createServer((s) => s.destroy());
    await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
    try {
      const port = (srv.address() as AddressInfo).port;
      expect((await LocalhostDetector.find([port]))?.port).toBe(port);
    } finally {
      await new Promise<void>((resolve) => srv.close(() => resolve()));
    }
  });
});

describe('verbose decision log', () => {
  let spy: jest.SpyInstance;
  beforeEach(() => {
    spy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => {
    setVerbose(false);
    spy.mockRestore();
  });
  const lines = () => spy.mock.calls.map((c) => c.slice(1).join(' '));

  it('logs one [probe], [skip] and [control] line per decision with --verbose', async () => {
    setVerbose(true);
    await withApp(
      (req, res) => (req.url?.startsWith('/__deployready_probe_') ? notFound(res) : json(res)),
      async (rec) => {
        await DynamicTester.run(rec.baseUrl, [route('GET', '/backoffice/stats'), route('GET', '/users/:id')]);
      },
    );
    const out = lines();
    expect(out).toContain(
      '[probe] GET /backoffice/stats: discovered at src/app.js:3; unguarded in code; admin-like: path segment "backoffice"',
    );
    expect(out.filter((l) => l.startsWith('[probe] GET /backoffice/stats'))).toHaveLength(1);
    expect(out.some((l) => /^\[skip\] GET \/users\/:id: needs a value for path parameter ":id"/.test(l))).toBe(true);
    expect(out.some((l) => /requested up to 3 times/.test(l))).toBe(true);
    const control = out.filter((l) => l.startsWith('[control] GET /__deployready_probe_'));
    expect(control).toHaveLength(1);
    expect(control[0]).toMatch(
      /random non-existent path, used only to recognise catch-all pages; sent because GET \/backoffice\/stats returned 200/,
    );
  });

  it('logs nothing without --verbose', async () => {
    await withApp(
      (_req, res) => json(res),
      async (rec) => {
        await DynamicTester.run(rec.baseUrl, [route('GET', '/ping'), route('GET', '/u/:id')]);
      },
    );
    expect(lines()).toEqual([]);
  });
});
