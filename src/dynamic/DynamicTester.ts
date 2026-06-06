/**
 * Orchestrates the dynamic suite against a confirmed-running local app.
 *
 * Interface contract (from spec):
 *   const results = await DynamicTester.run('http://localhost:3000', routes);
 *
 * Safety: target is loopback-validated by the http client; all probes are GET;
 * the aggressive rate-limit burst only runs when explicitly enabled.
 */
import { createClient } from './httpClient';
import { EndpointMapper } from './EndpointMapper';
import { SecurityTester } from './SecurityTester';
import { PerformanceTester } from './PerformanceTester';
import { APIAnalyzer } from './APIAnalyzer';
import type { DynamicResults, Route } from '../types';

export interface DynamicOptions {
  aggressive?: boolean;
}

export class DynamicTester {
  static async run(
    baseUrl: string,
    routes: Route[],
    opts: DynamicOptions = {},
  ): Promise<DynamicResults> {
    const client = createClient(baseUrl); // throws if non-loopback
    const targets = EndpointMapper.build(routes);

    const sec = await SecurityTester.run(client, targets, { aggressive: opts.aggressive ?? false });
    const [perf, api] = await Promise.all([
      PerformanceTester.run(client, targets),
      APIAnalyzer.run(client, targets),
    ]);

    return {
      baseUrl,
      reachable: true,
      endpoints: sec.endpoints,
      findings: [...sec.findings, ...perf, ...api],
    };
  }
}
