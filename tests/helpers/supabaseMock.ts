/** Mocked Supabase transport + key builders for the supabase-* tests. No real network. */
import type { SbResponse, Transport } from '../../src/supabase/http';

export function makeJwt(payload: Record<string, unknown>): string {
  const enc = (o: object): string => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${enc({ alg: 'HS256', typ: 'JWT' })}.${enc(payload)}.c2lnbmF0dXJlLXNpZ25hdHVyZQ`;
}

export const REF = 'abcdefghijklmnopqrst';
export const URL_HOSTED = `https://${REF}.supabase.co`;
export const ANON = makeJwt({ iss: 'supabase', ref: REF, role: 'anon' });
export const SERVICE = makeJwt({ iss: 'supabase', ref: REF, role: 'service_role' });
export const OTHER_SERVICE = makeJwt({ iss: 'supabase', ref: 'zzzzzzzzzzzzzzzzzzzz', role: 'service_role' });

export interface Sent {
  method: string;
  url: string;
  path: string;
  headers: Record<string, string>;
  body?: unknown;
}

export type Handler = (req: Sent) => Partial<SbResponse> | undefined;

/** A transport that records every request and answers from `handler` (default 404). */
export function mockTransport(handler: Handler): { transport: Transport; sent: Sent[] } {
  const sent: Sent[] = [];
  const transport: Transport = async (req) => {
    const u = new URL(req.url);
    const rec: Sent = { method: req.method, url: req.url, path: u.pathname + u.search, headers: req.headers, body: req.body };
    sent.push(rec);
    const r = handler(rec) ?? {};
    return { status: r.status ?? 404, headers: r.headers ?? {}, bodyText: r.bodyText ?? '' };
  };
  return { transport, sent };
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Partial<SbResponse> {
  return { status, bodyText: JSON.stringify(body), headers };
}

export function openApi(tables: Record<string, string[]>, rpc: string[] = []): string {
  const paths: Record<string, unknown> = { '/': {} };
  const definitions: Record<string, unknown> = {};
  for (const [t, cols] of Object.entries(tables)) {
    paths[`/${t}`] = {};
    definitions[t] = { properties: Object.fromEntries(cols.map((c) => [c, { type: 'string' }])) };
  }
  for (const f of rpc) paths[`/rpc/${f}`] = {};
  return JSON.stringify({ swagger: '2.0', paths, definitions });
}
