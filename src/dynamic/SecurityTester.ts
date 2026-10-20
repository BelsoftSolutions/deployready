/**
 * Runtime security checks against a live local app. GET-only by default.
 * The rate-limit probe sends a small burst and is only enabled when the caller
 * passes { aggressive: true } (gated behind explicit user consent upstream).
 */
import type { AxiosInstance } from 'axios';
import { makeFinding, makeNote } from '../utils/finding';
import { detectSecret } from '../utils/redact';
import type { Finding, LiveEndpoint, SkippedRoute } from '../types';
import type { ProbeTarget } from './EndpointMapper';
import { isCatchAll, probeCatchAll, type Fingerprint } from './catchAll';
import type { Resp } from './httpClient';

const SECURITY_HEADERS = [
  'x-content-type-options',
  'x-frame-options',
  'strict-transport-security',
  'content-security-policy',
];

const AUTH_LIKE = /login|auth|signin/i;

export interface SecurityRunResult {
  findings: Finding[];
  endpoints: LiveEndpoint[];
}

export class SecurityTester {
  static async run(
    client: AxiosInstance,
    targets: ProbeTarget[],
    opts: { aggressive: boolean; skipped?: SkippedRoute[]; prefetched?: Map<string, Resp | null> } = { aggressive: false },
  ): Promise<SecurityRunResult> {
    const findings: Finding[] = [];
    const endpoints: LiveEndpoint[] = [];
    let checkedHeaders = false;
    // CORS and security headers are server-wide config — report them once, not
    // once per endpoint, to keep the report signal high.
    let corsFlagged = false;
    let baseline: Promise<Fingerprint | null> | undefined;
    // Sent at most once, and only when a critical would otherwise be raised.
    const isCatchAllPage = async (t: ProbeTarget, res: { status: number; data: unknown }): Promise<boolean> => {
      baseline ??= probeCatchAll(client, `GET ${t.path} returned ${res.status} and would otherwise be reported`);
      return isCatchAll(await baseline, res);
    };
    const contentTypes = new Map<string, string>();

    for (const t of targets) {
      if (t.method !== 'GET') continue; // safety: never mutate
      let res;
      if (opts.prefetched?.has(t.path)) {
        res = opts.prefetched.get(t.path);
        if (!res) continue; // the earlier fetch got no response
      } else {
        try {
          res = await client.get(t.path);
        } catch {
          continue; // unreachable path — ignore
        }
      }
      endpoints.push({ method: 'GET', path: t.path, status: res.status });
      contentTypes.set(t.path, String(res.headers['content-type'] ?? ''));

      const reportable =
        (t.guarded || t.sensitive) && res.status >= 200 && res.status < 300 && !(await isCatchAllPage(t, res));

      // 1. Auth bypass: a guarded route that returns 2xx without credentials.
      if (t.guarded && reportable) {
        findings.push(
          makeFinding({
            rule: 'auth-bypass',
            title: 'Protected endpoint reachable without authentication',
            severity: 'critical',
            category: 'security',
            source: 'dynamic',
            endpoint: t.path,
            owasp: 'A01:2025',
            cwe: 'CWE-306',
            description: `${t.path} appeared auth-guarded in code but returned ${res.status} with no token.`,
            recommendation: 'Enforce authentication middleware on this route and verify it returns 401/403 when unauthenticated.',
          }),
        );
      }

      // 2. Exposed sensitive/admin route.
      if (t.sensitive && reportable) {
        findings.push(
          makeFinding({
            rule: 'exposed-admin-route',
            title: 'Sensitive route is publicly reachable',
            severity: 'critical',
            category: 'security',
            source: 'dynamic',
            endpoint: t.path,
            owasp: 'A01:2025',
            cwe: 'CWE-284',
            description: `${t.path} returned ${res.status} without authentication.`,
            recommendation: 'Restrict admin/debug routes behind authentication and authorization, or remove them from production.',
          }),
        );
      }

      // 3. Secret leakage in response body. A matched key shape is a critical;
      // a merely secret-named value is a warning (could be a benign field name).
      const body = typeof res.data === 'string' ? res.data : safeStringify(res.data);
      const secret = body ? detectSecret(body) : null;
      if (secret) {
        const high = secret === 'high';
        findings.push(
          makeFinding({
            rule: 'secret-in-response',
            title: high
              ? 'API response contains a hardcoded secret / credential'
              : 'API response contains a secret-like value',
            severity: high ? 'critical' : 'warning',
            category: 'security',
            source: 'dynamic',
            endpoint: t.path,
            owasp: 'A02:2025',
            cwe: 'CWE-200',
            description: `Response from ${t.path} contained a value matching a secret pattern.`,
            recommendation: 'Remove credentials/tokens from API responses. Return only the minimum data the client needs.',
          }),
        );
      }

      // 4. CORS: reflected/wildcard origin (report once — it's server-wide).
      const acao = String(res.headers['access-control-allow-origin'] ?? '');
      if (acao === '*' && !corsFlagged) {
        corsFlagged = true;
        findings.push(
          makeFinding({
            rule: 'cors-wildcard-live',
            title: 'Server returns Access-Control-Allow-Origin: *',
            severity: 'warning',
            category: 'security',
            source: 'dynamic',
            owasp: 'A02:2025',
            cwe: 'CWE-942',
            description: `The server responds with a wildcard CORS origin (first seen at ${t.path}).`,
            recommendation: 'Restrict CORS to specific trusted origins; never combine "*" with credentialed requests.',
          }),
        );
      }

      // 5. Missing security headers (check once, on first 2xx HTML/JSON response).
      if (!checkedHeaders && res.status >= 200 && res.status < 300) {
        checkedHeaders = true;
        const missing = SECURITY_HEADERS.filter((h) => !(h in res.headers));
        if (missing.length) {
          findings.push(
            makeFinding({
              rule: 'missing-security-headers',
              title: 'Missing recommended security headers',
              severity: 'warning',
              category: 'security',
              source: 'dynamic',
              endpoint: t.path,
              owasp: 'A02:2025',
              cwe: 'CWE-693',
              description: `Response is missing: ${missing.join(', ')}.`,
              recommendation: 'Add a security-headers middleware (e.g. helmet) to set CSP, HSTS, X-Frame-Options, and X-Content-Type-Options.',
            }),
          );
        }
      }
    }

    // 6. Rate limiting (aggressive — burst a likely-auth endpoint).
    if (opts.aggressive) {
      // A login PAGE (HTML) says nothing about the login API's throttling, so only
      // non-HTML auth-like GET endpoints are burst.
      const isBurstable = (t: ProbeTarget) =>
        t.method === 'GET' && AUTH_LIKE.test(t.path) && contentTypes.has(t.path) && !/text\/html/i.test(contentTypes.get(t.path)!);
      const loginTarget = targets.find(isBurstable);
      const burstPaths = new Set(targets.filter(isBurstable).map((t) => t.path));
      if (loginTarget) {
        const f = await SecurityTester.probeRateLimit(client, loginTarget.path);
        if (f) findings.push(f);
      }
      // Auth-like routes we cannot test (non-GET, or only an HTML page): never go
      // silent, but never claim a limiter is missing either.
      const noted = new Set<string>();
      const nonGetSkipped = (opts.skipped ?? []).filter((s) => s.method !== 'GET');
      for (const t of [...targets, ...nonGetSkipped]) {
        if (!AUTH_LIKE.test(t.path) || burstPaths.has(t.path) || noted.has(t.path)) continue;
        noted.add(t.path);
        findings.push(SecurityTester.unverifiedRateLimitNote(t.path));
      }
    }

    return { findings, endpoints };
  }

  private static unverifiedRateLimitNote(path: string): Finding {
    return makeNote({
      rule: 'missing-rate-limit',
      title: `Rate limiting on ${path} could not be verified`,
      category: 'security',
      source: 'dynamic',
      endpoint: path,
      owasp: 'A07:2025',
      cwe: 'CWE-307',
      description: `${path} looks like an authentication route, but the scanner only sends GET requests, so this route was not tested for rate limiting. This does not mean a limiter is missing.`,
      recommendation: `Check that a rate limiter (e.g. express-rate-limit) is configured on ${path}.`,
    });
  }

  /** Send a small burst; if nothing ever returns 429, flag missing rate limiting. */
  private static async probeRateLimit(client: AxiosInstance, path: string): Promise<Finding | null> {
    const BURST = 20;
    let throttled = false;
    for (let i = 0; i < BURST; i++) {
      try {
        const res = await client.get(path);
        if (res.status === 429) {
          throttled = true;
          break;
        }
      } catch {
        break;
      }
    }
    if (throttled) return null;
    return makeFinding({
      rule: 'missing-rate-limit',
      title: 'No rate limiting detected on sensitive endpoint',
      severity: 'warning',
      category: 'security',
      source: 'dynamic',
      endpoint: path,
      owasp: 'A07:2025',
      cwe: 'CWE-307',
      description: `Sent ${BURST} rapid GET requests to ${path} with no 429 throttling response. Low confidence: measured with GET requests only; the login POST route itself is not probed.`,
      recommendation: 'Add rate limiting (e.g. express-rate-limit) to auth and other abuse-prone endpoints.',
    });
  }
}

function safeStringify(data: unknown): string {
  try {
    return (JSON.stringify(data) ?? '').slice(0, 100_000);
  } catch {
    return '';
  }
}
