/**
 * Orchestrates the dynamic suite against a confirmed-running local app.
 *
 * Interface contract (from spec):
 *   const results = await DynamicTester.run('http://localhost:3000', routes);
 *
 * Safety: target is loopback-validated by the http client; all probes are GET;
 * only routes discovered by static analysis or declared in the project's own API
 * description, plus paths the running app advertised in responses already
 * fetched from them (advertised.ts), are ever requested (no guessed paths, no
 * invented ids); the aggressive rate-limit burst only runs when
 * explicitly enabled.
 */
import { createClient } from './httpClient';
import { EndpointMapper } from './EndpointMapper';
import { SecurityTester } from './SecurityTester';
import { PerformanceTester } from './PerformanceTester';
import { APIAnalyzer } from './APIAnalyzer';
import { discoverAdvertised } from './advertised';
import { makeNote } from '../utils/finding';
import { logger } from '../utils/logger';
import type { DynamicResults, Finding, Route, SkippedRoute } from '../types';

export interface DynamicOptions {
  aggressive?: boolean;
  /** Project root; lets robots.txt / sitemap.xml files in its static dirs count as evidence. */
  projectPath?: string;
}

const MAX_LISTED = 10;

function groupReasons(skipped: SkippedRoute[]): string {
  const byReason = new Map<string, number>();
  for (const s of skipped) byReason.set(s.reason, (byReason.get(s.reason) ?? 0) + 1);
  return [...byReason].map(([reason, n]) => `${n} x ${reason}`).join('; ');
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

/** Non-scored note for a scan that sent nothing, with the reason. */
export function skippedScanNote(
  rule: 'dynamic-skipped' | 'active-skipped',
  routeCount: number,
  skipped: SkippedRoute[],
): Finding {
  const scan = rule === 'dynamic-skipped' ? 'dynamic' : 'active';
  if (routeCount === 0) {
    return makeNote({
      rule,
      title: `No routes discovered; ${scan} checks skipped`,
      category: 'security',
      source: 'dynamic',
      description:
        'Static analysis found no routes in this project (for example, the framework is not supported). DeployReady does not guess routes, so nothing was requested from your running app.',
      recommendation: 'Run DeployReady on a project with a supported framework, or review the live app with another tool.',
    });
  }
  return makeNote({
    rule,
    title: `${plural(routeCount, 'route')} discovered but none could be probed; ${scan} checks skipped`,
    category: 'security',
    source: 'dynamic',
    description: `Routes were found in the code, but none can be requested safely without inventing a path or value. Nothing was requested. Reasons: ${groupReasons(skipped)}.`,
    recommendation:
      scan === 'dynamic'
        ? 'For routes with path parameters, use the authenticated active scan (--token), which fills them from your own token.'
        : 'Provide a token whose claims can fill the path parameters, or review these routes manually.',
  });
}

function skippedRoutesNote(skipped: SkippedRoute[], probedCount: number): Finding {
  const listed = skipped
    .slice(0, MAX_LISTED)
    .map((s) => `${s.method} ${s.path} (${s.reason})`)
    .join('; ');
  const more = skipped.length > MAX_LISTED ? `; and ${skipped.length - MAX_LISTED} more` : '';
  return makeNote({
    rule: 'dynamic-routes-skipped',
    title: `${plural(skipped.length, 'discovered route')} could not be checked dynamically`,
    category: 'security',
    source: 'dynamic',
    description: `${plural(probedCount, 'discovered route')} checked; ${skipped.length} not requested because DeployReady never guesses paths or values: ${listed}${more}.`,
    recommendation: 'Review these routes manually, or use the authenticated active scan (--token) for routes that need a path parameter.',
  });
}

export class DynamicTester {
  static async run(
    baseUrl: string,
    routes: Route[],
    opts: DynamicOptions = {},
  ): Promise<DynamicResults> {
    const client = createClient(baseUrl); // throws if non-loopback
    const { targets, skipped } = EndpointMapper.plan(routes);

    for (const s of skipped) logger.debug(`[skip] ${s.method} ${s.path}: ${s.reason}`);
    for (const t of targets) logger.debug(`[probe] ${t.method} ${t.path}: ${t.why.join('; ')}`);

    if (targets.length === 0) {
      // With no targets this sends nothing; it only keeps the "could not verify" rate-limit notes.
      const sec = await SecurityTester.run(client, [], { aggressive: opts.aggressive ?? false, skipped });
      return {
        baseUrl,
        reachable: true,
        endpoints: [],
        probed: [],
        skipped,
        findings: [skippedScanNote('dynamic-skipped', routes.length, skipped), ...sec.findings],
      };
    }
    logger.debug(
      `[probe] ${plural(targets.length, 'discovered route')} will be requested; each is requested up to 3 times (security, performance and API checks)`,
    );

    const advertised = await discoverAdvertised(client, baseUrl, targets, opts.projectPath);
    for (const t of advertised.targets) logger.debug(`[probe] ${t.method} ${t.path}: ${t.why.join('; ')}`);
    const all = [...targets, ...advertised.targets];

    const sec = await SecurityTester.run(client, all, {
      aggressive: opts.aggressive ?? false,
      skipped,
      prefetched: advertised.responses,
    });
    const [perf, api] = await Promise.all([PerformanceTester.run(client, all), APIAnalyzer.run(client, all)]);

    const findings = [...sec.findings, ...perf, ...api];
    if (skipped.length > 0) findings.push(skippedRoutesNote(skipped, targets.length));

    return {
      baseUrl,
      reachable: true,
      endpoints: sec.endpoints,
      probed: all.map(({ method, path, why }) => ({ method, path, why })),
      skipped,
      findings,
    };
  }
}
