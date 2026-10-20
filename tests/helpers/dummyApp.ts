import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import type { AddressInfo } from 'net';

export interface Recorded {
  method: string;
  url: string;
  path: string;
}

export interface DummyApp {
  baseUrl: string;
  port: number;
  requests: Recorded[];
  paths: () => string[];
  close: () => Promise<void>;
}

export type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

export const CONTROL_PATH = /^\/__deployready_probe_/;

export async function startApp(handler: Handler): Promise<DummyApp> {
  const requests: Recorded[] = [];
  const server = http.createServer((req, res) => {
    const url = req.url ?? '/';
    requests.push({ method: req.method ?? '?', url, path: url.split('?')[0] ?? '/' });
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    port,
    requests,
    paths: () => requests.map((r) => r.path),
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

export async function withApp<T>(handler: Handler, fn: (app: DummyApp) => Promise<T>): Promise<T> {
  const app = await startApp(handler);
  try {
    return await fn(app);
  } finally {
    await app.close();
  }
}

export function send(res: http.ServerResponse, status: number, body: string, type = 'text/html', headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': type, ...headers });
  res.end(body);
}

/** Serves `openPaths` with distinct 200 bodies, answers `statusFor` (default 404) elsewhere. */
export function appServing(openPaths: string[], elsewhere: (res: http.ServerResponse, p: string) => void = (res) => send(res, 404, 'not found', 'text/plain')): Handler {
  return (req, res) => {
    const p = (req.url ?? '/').split('?')[0] ?? '/';
    if (openPaths.includes(p)) return send(res, 200, `<h1>Private area ${p}</h1><p>records, users, billing</p>`);
    elsewhere(res, p);
  };
}

export function writeProject(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-dummy-app-'));
  fs.writeFileSync(path.join(dir, '.gitignore'), '.env\nnode_modules\n');
  for (const [name, body] of Object.entries(files)) {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, body);
  }
  return dir;
}

export function expressProject(routeLines: string[], extra: Record<string, string> = {}): string {
  const src = ["const express = require('express');", 'const app = express();', ...routeLines, 'app.listen(3000);', ''].join('\n');
  return writeProject({
    'package.json': JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: { express: '^4.18.0' } }),
    'server.js': src,
    ...extra,
  });
}

/** An unsigned JWT with dummy claims; never a real credential. */
export function dummyJwt(claims: Record<string, unknown>): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(claims)}.dummy-signature`;
}

export const NEVER_GUESSED = ['/admin', '/api/admin', '/.env', '/debug', '/actuator', '/api/users', '/health', '/status', '/metrics', '/api', '/'];

/** A path the parser would call concrete: absolute, no parameter or pattern syntax. */
export function isConcrete(p: string): boolean {
  return p.startsWith('/') && !/[:{}<>*()?+[\]\\]/.test(p);
}
