/**
 * Runtime performance checks: response time + caching behavior. GET-only.
 */
import type { AxiosInstance } from 'axios';
import { makeFinding } from '../utils/finding';
import type { Finding } from '../types';
import type { ProbeTarget } from './EndpointMapper';
import { absoluteUrl, buildProof } from './proof';

const SLOW_MS = 1000;

export class PerformanceTester {
  static async run(client: AxiosInstance, targets: ProbeTarget[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    // Test a bounded sample of reachable GET endpoints.
    const baseUrl = client.defaults?.baseURL;
    const sample = targets.filter((t) => t.method === 'GET').slice(0, 25);

    for (const t of sample) {
      const first = await timeRequest(client, t.path);
      if (!first) continue;

      // Slow endpoint.
      if (first.ms > SLOW_MS) {
        findings.push(
          makeFinding({
            rule: 'slow-endpoint',
            title: 'Slow endpoint response time',
            severity: 'warning',
            category: 'performance',
            source: 'dynamic',
            endpoint: t.path,
            description: `${t.path} took ${first.ms}ms to respond (threshold ${SLOW_MS}ms).`,
            recommendation: 'Profile the handler, add caching, and check for N+1 database queries.',
            proof: buildProof({
              request: { method: 'GET', url: absoluteUrl(baseUrl, t.path) },
              status: first.status,
              response: `Responded in ${first.ms}ms (threshold ${SLOW_MS}ms).`,
            }),
          }),
        );
      }

      // Missing cache headers on a cacheable GET.
      if (first.status >= 200 && first.status < 300 && !first.hasCacheControl) {
        findings.push(
          makeFinding({
            rule: 'missing-cache-headers',
            title: 'No Cache-Control on cacheable GET endpoint',
            severity: 'info',
            category: 'performance',
            source: 'dynamic',
            endpoint: t.path,
            description: `${t.path} returned no Cache-Control header.`,
            recommendation: 'Set appropriate Cache-Control headers (or ETag) on cacheable responses to reduce load and latency.',
            proof: buildProof({
              request: { method: 'GET', url: absoluteUrl(baseUrl, t.path) },
              status: first.status,
              response: 'Response headers lack: cache-control, etag',
            }),
          }),
        );
      }
    }

    return findings;
  }
}

async function timeRequest(
  client: AxiosInstance,
  path: string,
): Promise<{ ms: number; status: number; hasCacheControl: boolean } | null> {
  const start = Date.now();
  try {
    const res = await client.get(path);
    return {
      ms: Date.now() - start,
      status: res.status,
      hasCacheControl: 'cache-control' in res.headers || 'etag' in res.headers,
    };
  } catch {
    return null;
  }
}
