import type { Finding, Route } from '../src/types';

export type CaseKind = 'static' | 'parser' | 'dynamic' | 'active';

export interface FindingExpectation {
  rule: string;
  present: boolean;
  file?: string;
  endpoint?: string;
  severity?: string;
}

export interface RouteExpectation {
  route: { method: string; path: string };
  guarded: boolean;
}

export type Expectation = FindingExpectation | RouteExpectation;

/** One labelled yes/no question about a case: expected vs what the tool did. */
export interface Check {
  rule: string;
  label: string;
  expected: boolean;
  actual: boolean;
  detail: string;
}

export interface BenchCase {
  id: string;
  kind: CaseKind;
  description: string;
  knownGap?: string;
  evaluate(): Promise<Check[]>;
}

export const ROUTE_GUARD_RULE = 'route-guarded';

export function isRouteExpectation(e: Expectation): e is RouteExpectation {
  return 'route' in e;
}

function where(f: Finding): string {
  const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : (f.endpoint ?? '?');
  return `${loc}${f.severity ? ` ${f.severity}` : ''}`;
}

export function checkFindings(findings: Finding[], expected: FindingExpectation[]): Check[] {
  return expected.map((e) => {
    const matches = findings.filter(
      (f) =>
        f.rule === e.rule &&
        (e.file === undefined || f.file === e.file) &&
        (e.endpoint === undefined || f.endpoint === e.endpoint) &&
        (e.severity === undefined || f.severity === e.severity),
    );
    const scope = [e.file, e.endpoint, e.severity].filter((x) => x !== undefined).join(' ');
    const actual = matches.length > 0;
    const seen = matches.map(where).sort().slice(0, 5).join(', ');
    return {
      rule: e.rule,
      label: `${e.rule} ${e.present ? 'present' : 'absent'}${scope ? ` (${scope})` : ''}`,
      expected: e.present,
      actual,
      detail: actual ? `found ${matches.length}: ${seen}` : 'not found',
    };
  });
}

export function checkRoutes(routes: Route[], expected: RouteExpectation[]): Check[] {
  return expected.map((e) => {
    const method = e.route.method.toUpperCase();
    const hit = routes.find((r) => r.method.toUpperCase() === method && r.path === e.route.path);
    if (!hit) {
      const known = routes.map((r) => `${r.method} ${r.path}`).sort().join(', ');
      throw new Error(`route ${method} ${e.route.path} not discovered (parser saw: ${known || 'no routes'})`);
    }
    return {
      rule: ROUTE_GUARD_RULE,
      label: `${method} ${e.route.path} ${e.guarded ? 'guarded' : 'unguarded'}`,
      expected: e.guarded,
      actual: hit.guarded,
      detail: hit.guarded ? 'parser: guarded' : 'parser: unguarded',
    };
  });
}
