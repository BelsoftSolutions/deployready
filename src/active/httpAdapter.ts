/**
 * The real network transport for the active scan (Phase 5a) — the ONE place that
 * actually sends requests, so it carries the safety rails:
 *   - loopback-only target (SSRF/scope guard, same bar as the dynamic suite),
 *     re-checked on every derived URL so a request can never leave the host;
 *   - dry-run that sends nothing;
 *   - hard timeout, no redirects, response-size cap.
 *
 * It returns the minimal `ActiveResponse` the runner needs. Consent + the request
 * budget live above this (Orchestrator + runner).
 */
import axios from 'axios';
import { assertLoopback } from '../dynamic/httpClient';
import type { HttpFn } from './runner';

const TIMEOUT_MS = 8000;
const MAX_BODY = 5 * 1024 * 1024;

/** Build an absolute URL from base + path (+ query). Pure. */
export function buildUrl(baseUrl: string, path: string, query?: Record<string, string | number>): string {
  const url = new URL(path, baseUrl);
  if (query) {
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, String(v));
  }
  return url.toString();
}

export interface ActiveAdapterOptions {
  baseUrl: string;
  /** When true, send nothing — return a non-2xx sentinel so the runner no-ops. */
  dryRun?: boolean;
  timeoutMs?: number;
}

export function createActiveHttpAdapter(opts: ActiveAdapterOptions): HttpFn {
  assertLoopback(opts.baseUrl); // scope is fixed to this loopback host
  const timeout = opts.timeoutMs ?? TIMEOUT_MS;

  return async (req) => {
    const url = buildUrl(opts.baseUrl, req.path, req.query);
    assertLoopback(url); // defense in depth: never leave the loopback host

    if (opts.dryRun) return { status: 0, bodyText: '' };

    const res = await axios.request({
      url,
      method: req.method as never,
      headers: { 'User-Agent': 'DeployReady-Scanner/0.1', ...req.headers },
      data: req.body,
      timeout,
      maxRedirects: 0,
      validateStatus: () => true,
      maxContentLength: MAX_BODY,
    });
    const bodyText = typeof res.data === 'string' ? res.data : JSON.stringify(res.data ?? '');
    return { status: res.status, bodyText };
  };
}
