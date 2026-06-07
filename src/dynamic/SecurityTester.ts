/**
 * Runtime security checks against a live local app. GET-only by default.
 * The rate-limit probe sends a small burst and is only enabled when the caller
 * passes { aggressive: true } (gated behind explicit user consent upstream).
 */
import type { AxiosInstance } from 'axios';
import { makeFinding } from '../utils/finding';
import { detectSecret, redact } from '../utils/redact';
import type { Finding, LiveEndpoint } from '../types';
import type { ProbeTarget } from './EndpointMapper';

const SECURITY_HEADERS = [
  'x-content-type-options',
  'x-frame-options',
  'strict-transport-security',
  'content-security-policy',
];

export interface SecurityRunResult {
  findings: Finding[];
  endpoints: LiveEndpoint[];
}

export class SecurityTester {
  static async run(
    client: AxiosInstance,
    targets: ProbeTarget[],
    opts: { aggressive: boolean } = { aggressive: false },
  ): Promise<SecurityRunResult> {
    const findings: Finding[] = [];
    const endpoints: LiveEndpoint[] = [];
    let checkedHeaders = false;
    // CORS and security headers are server-wide config — report them once, not
    // once per endpoint, to keep the report signal high.
    let corsFlagged = false;

    for (const t of targets) {
      if (t.method !== 'GET') continue; // safety: never mutate
      let res;
      try {
        res = await client.get(t.path);
      } catch {
        continue; // unreachable path — ignore
      }
      endpoints.push({ method: 'GET', path: t.path, status: res.status });

      // 1. Auth bypass: a guarded route that returns 2xx without credentials.
      if (t.guarded && res.status >= 200 && res.status < 300) {
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
      if (t.sensitive && res.status >= 200 && res.status < 400) {
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
      const loginTarget = targets.find((t) => /login|auth|signin/i.test(t.path));
      if (loginTarget) {
        const f = await SecurityTester.probeRateLimit(client, loginTarget.path);
        if (f) findings.push(f);
      }
    }

    return { findings, endpoints };
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
      severity: 'critical',
      category: 'security',
      source: 'dynamic',
      endpoint: path,
      owasp: 'A07:2025',
      cwe: 'CWE-307',
      description: `Sent ${BURST} rapid requests to ${path} with no 429 throttling response.`,
      recommendation: 'Add rate limiting (e.g. express-rate-limit) to auth and other abuse-prone endpoints.',
    });
  }
}

function safeStringify(data: unknown): string {
  try {
    return redact(JSON.stringify(data)).slice(0, 100_000);
  } catch {
    return '';
  }
}
