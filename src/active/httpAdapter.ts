/**
 * The real network transport for the active scan (Phase 5a) — the ONE place that
 * actually sends requests, so it carries the safety rails:
 *   - loopback-only target by default (SSRF/scope guard, same bar as the
 *     dynamic suite); a non-loopback host only when the user explicitly confirmed
 *     they own it (`ownedHosts`), re-checked on every derived URL so a request
 *     can never leave the host;
 *   - dry-run that sends nothing;
 *   - a hard request budget for the whole run (`maxRequests`): once used up,
 *     every further call throws `ActiveBudgetError` and nothing is sent;
 *   - redirects: never followed across hosts; a same-host redirect of a GET is
 *     followed (at most 3 hops) only after the scope check passes again for the
 *     new URL; other methods never follow redirects;
 *   - hard timeout, response-size cap.
 *
 * It returns the minimal `ActiveResponse` the runner needs. Consent lives above
 * this (Orchestrator).
 */
import axios from 'axios';
import { assertActiveTarget } from './scope';
import { ActiveBudgetError } from './safety';
import type { HttpFn } from './runner';

const TIMEOUT_MS = 8000;
const MAX_BODY = 5 * 1024 * 1024;
const MAX_REDIRECT_HOPS = 3;

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
  /**
   * Non-loopback hosts the user explicitly confirmed they own (validated with
   * `parseOwnedHosts`). Empty/absent = loopback only.
   */
  ownedHosts?: readonly string[];
  /** Hard cap on requests sent through this adapter (all checks together). Default: unlimited here. */
  maxRequests?: number;
  /** Called once per request actually sent (method + absolute URL), e.g. for an audit log. */
  onSend?: (method: string, url: string) => void;
}

export function createActiveHttpAdapter(opts: ActiveAdapterOptions): HttpFn {
  const owned = opts.ownedHosts ?? [];
  const base = assertActiveTarget(opts.baseUrl, owned); // scope is fixed to this host
  const timeout = opts.timeoutMs ?? TIMEOUT_MS;

  let sent = 0;
  const max = opts.maxRequests ?? Infinity;

  /** Scope check for every URL we are about to hit (the first one and every redirect hop). */
  const inScope = (url: string): URL => {
    const target = assertActiveTarget(url, owned);
    if (target.host !== base.host) {
      throw new Error(`Refusing to send an active probe to ${target.host}: outside the scan target ${base.host}.`);
    }
    return target;
  };

  return async (req) => {
    let url = buildUrl(opts.baseUrl, req.path, req.query);
    // Defense in depth: never leave the base host, even if a path is absolute.
    inScope(url);

    if (opts.dryRun) return { status: 0, bodyText: '' };

    const method = req.method.toUpperCase();
    for (let hop = 0; ; hop++) {
      if (sent >= max) throw new ActiveBudgetError(max);
      sent++;
      opts.onSend?.(method, url);
      const res = await axios.request({
        url,
        method: method as never,
        headers: { 'User-Agent': 'DeployReady-Scanner/0.1', ...req.headers },
        data: req.body,
        timeout,
        maxRedirects: 0,
        validateStatus: () => true,
        maxContentLength: MAX_BODY,
      });
      const bodyText = typeof res.data === 'string' ? res.data : JSON.stringify(res.data ?? '');
      const location = res.headers?.location as string | undefined;
      const redirect = res.status >= 300 && res.status < 400 && typeof location === 'string' && location !== '';
      if (!redirect || (method !== 'GET' && method !== 'HEAD') || hop >= MAX_REDIRECT_HOPS) {
        return { status: res.status, bodyText, url };
      }
      let next: string;
      try {
        next = new URL(location, url).toString();
        inScope(next); // re-check scope on every hop
      } catch {
        // Cross-host (or otherwise out-of-scope) redirect: not followed; the 3xx is the answer.
        return { status: res.status, bodyText, url };
      }
      url = next;
    }
  };
}
