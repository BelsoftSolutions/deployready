/**
 * Inspect API responses for information leaks beyond raw secrets: stack traces,
 * server/framework version banners, and verbose error payloads.
 */
import type { AxiosInstance } from 'axios';
import { makeFinding } from '../utils/finding';
import type { Finding } from '../types';
import type { ProbeTarget } from './EndpointMapper';

const STACK_TRACE_RE = /\b(?:at\s+[\w.$]+\s*\(|Traceback \(most recent call last\)|Exception in|\.java:\d+\))/;

export class APIAnalyzer {
  static async run(client: AxiosInstance, targets: ProbeTarget[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    let bannerChecked = false;

    for (const t of targets.filter((x) => x.method === 'GET').slice(0, 25)) {
      let res;
      try {
        res = await client.get(t.path);
      } catch {
        continue;
      }

      // Verbose server banner (leaks framework/version → targeted exploits).
      if (!bannerChecked) {
        bannerChecked = true;
        const banner = String(res.headers['x-powered-by'] ?? res.headers['server'] ?? '');
        if (banner && /\d/.test(banner)) {
          findings.push(
            makeFinding({
              rule: 'version-banner',
              title: 'Server discloses software version',
              severity: 'info',
              category: 'security',
              source: 'dynamic',
              endpoint: t.path,
              owasp: 'A02:2025',
              cwe: 'CWE-200',
              description: `Response advertises "${banner}" via Server/X-Powered-By header.`,
              recommendation: 'Disable version banners (e.g. app.disable("x-powered-by")) so attackers cannot fingerprint your stack.',
            }),
          );
        }
      }

      // Stack trace / verbose error in body (esp. on 5xx).
      const body = typeof res.data === 'string' ? res.data : tryStringify(res.data);
      if (body && STACK_TRACE_RE.test(body)) {
        findings.push(
          makeFinding({
            rule: 'stack-trace-leak',
            title: 'Stack trace exposed in HTTP response',
            severity: 'warning',
            category: 'security',
            source: 'dynamic',
            endpoint: t.path,
            owasp: 'A10:2025',
            cwe: 'CWE-209',
            description: `${t.path} (status ${res.status}) returned a stack trace / internal error detail.`,
            recommendation: 'Return generic error messages to clients; log full details server-side only. Disable debug mode in production.',
          }),
        );
      }
    }

    return findings;
  }
}

function tryStringify(data: unknown): string {
  try {
    return JSON.stringify(data).slice(0, 50_000);
  } catch {
    return '';
  }
}
