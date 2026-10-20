import * as http from 'http';
import type { AddressInfo } from 'net';
import { runCommonPathProbe } from '../../src/dynamic/commonPaths/prober';
import type { CommonPathOptions } from '../../src/dynamic/commonPaths/prober';

export interface Reply {
  status?: number;
  type?: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
}

export type RouteMap = Record<string, Reply>;

export interface Recorded {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
}

export const PLAIN_404: Reply = { status: 404, type: 'text/plain', body: 'not found' };

/** Dummy server on 127.0.0.1:0 that records every request. Unknown paths get `fallback`. */
export async function withServer<T>(
  handler: (req: http.IncomingMessage, res: http.ServerResponse, seen: Recorded[]) => void,
  fn: (baseUrl: string, seen: Recorded[]) => Promise<T>,
): Promise<T> {
  const seen: Recorded[] = [];
  const server = http.createServer((req, res) => {
    seen.push({ method: req.method ?? '', path: req.url ?? '', headers: req.headers });
    handler(req, res, seen);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    return await fn(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen);
  } finally {
    server.closeAllConnections?.();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

export function send(res: http.ServerResponse, r: Reply): void {
  res.writeHead(r.status ?? 200, { 'content-type': r.type ?? 'text/plain', ...(r.headers ?? {}) });
  res.end(r.body ?? '');
}

/** Run the probe against a server answering from `routes`, everything else with `fallback`. */
export function probeRoutes(routes: RouteMap, opts: Partial<CommonPathOptions> = {}, fallback: Reply = PLAIN_404) {
  return withServer(
    (req, res) => send(res, routes[req.url ?? ''] ?? fallback),
    async (baseUrl, seen) => {
      const result = await runCommonPathProbe(baseUrl, { exclude: [], delayMs: 0, ...opts });
      return { ...result, seen, baseUrl };
    },
  );
}

export const html = (body: string): Reply => ({ type: 'text/html; charset=utf-8', body });
export const json = (v: unknown): Reply => ({ type: 'application/json', body: JSON.stringify(v) });
export const text = (body: string | Buffer): Reply => ({ type: 'text/plain', body });
