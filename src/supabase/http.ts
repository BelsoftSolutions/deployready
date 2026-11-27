/**
 * The ONE network client for the Supabase module. Every live Supabase request
 * goes through `SupabaseHttp`, which carries the safety rails:
 *   - fixed origin: a client is bound to one origin (the project URL, or the
 *     Management API) and refuses any URL that resolves elsewhere;
 *   - https only, except for a loopback (local `supabase start`) origin;
 *   - rate limit (minimum spacing between requests) and a hard request budget;
 *   - timeout, no redirects, response-size cap (in the default transport).
 *
 * The transport is injected so tests mock it and no real network is touched.
 */
import axios from 'axios';

export interface SbRequest {
  method: 'GET' | 'HEAD' | 'POST';
  /** Path (with leading slash) relative to the client's origin. */
  path: string;
  query?: Record<string, string | number>;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface SbResponse {
  status: number;
  /** Lower-cased header names. */
  headers: Record<string, string>;
  bodyText: string;
}

/** Sends one fully-built request. The only thing tests replace. */
export type Transport = (req: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: unknown;
}) => Promise<SbResponse>;

export interface SupabaseHttpOptions {
  /** Origin this client may talk to, e.g. https://abc.supabase.co. */
  origin: string;
  transport?: Transport;
  /** Minimum ms between two requests (default 250). Tests set 0. */
  minIntervalMs?: number;
  /** Hard cap on requests sent by this client (default 300). */
  maxRequests?: number;
  /** Injected for tests. */
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
const TIMEOUT_MS = 10_000;
const MAX_BODY = 5 * 1024 * 1024;
const USER_AGENT = 'DeployReady-Supabase-Check';

export function isLoopbackUrl(raw: string): boolean {
  try {
    const host = new URL(raw).hostname;
    return LOOPBACK.has(host) || host.endsWith('.localhost');
  } catch {
    return false;
  }
}

/** Real transport: axios, no redirects, bounded time and size, never throws on status. */
export const axiosTransport: Transport = async (req) => {
  const res = await axios.request({
    url: req.url,
    method: req.method as never,
    headers: { 'User-Agent': USER_AGENT, ...req.headers },
    data: req.body,
    timeout: TIMEOUT_MS,
    maxRedirects: 0,
    validateStatus: () => true,
    maxContentLength: MAX_BODY,
    responseType: 'text',
    transformResponse: (d: unknown) => d,
  });
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(res.headers ?? {})) {
    if (v !== undefined && v !== null) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return { status: res.status, headers, bodyText: typeof res.data === 'string' ? res.data : '' };
};

export class BudgetExceededError extends Error {}

export class SupabaseHttp {
  readonly origin: string;
  private readonly transport: Transport;
  private readonly minIntervalMs: number;
  private readonly maxRequests: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private last = 0;
  private chain: Promise<unknown> = Promise.resolve();
  sent = 0;

  constructor(opts: SupabaseHttpOptions) {
    const url = new URL(opts.origin);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopbackUrl(opts.origin))) {
      throw new Error('Supabase checks require an https:// URL (plain http is only allowed for a local, loopback project).');
    }
    this.origin = url.origin;
    this.transport = opts.transport ?? axiosTransport;
    this.minIntervalMs = opts.minIntervalMs ?? 250;
    this.maxRequests = opts.maxRequests ?? 300;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.now = opts.now ?? Date.now;
  }

  /** Build the absolute URL and refuse anything that leaves this client's origin. */
  buildUrl(path: string, query?: Record<string, string | number>): string {
    const url = new URL(path, this.origin + '/');
    if (url.origin !== this.origin) throw new Error('Refusing a request outside the configured Supabase origin.');
    if (query) for (const [k, v] of Object.entries(query)) url.searchParams.set(k, String(v));
    return url.toString();
  }

  /** Send one request, serialized and rate-limited. */
  request(req: SbRequest): Promise<SbResponse> {
    const run = async (): Promise<SbResponse> => {
      if (this.sent >= this.maxRequests) {
        throw new BudgetExceededError(`Supabase request budget (${this.maxRequests}) reached; stopping.`);
      }
      const url = this.buildUrl(req.path, req.query);
      const wait = this.last + this.minIntervalMs - this.now();
      if (this.sent > 0 && wait > 0) await this.sleep(wait);
      this.sent++;
      this.last = this.now();
      const headers = { ...(req.headers ?? {}) };
      if (req.body !== undefined && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
      return this.transport({ method: req.method, url, headers, body: req.body });
    };
    const p = this.chain.then(run, run);
    this.chain = p.catch(() => undefined);
    return p;
  }
}
