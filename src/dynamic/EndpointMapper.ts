/**
 * Decide which discovered routes the dynamic scan may request. Only routes
 * found by static analysis ever become targets: no common-path list, no
 * invented ids. Anything that cannot be requested as-is is reported as skipped.
 */
import type { Route, SkippedRoute } from '../types';
import { adminEvidence } from './adminEvidence';

export type { SkippedRoute };

export interface ProbeTarget {
  method: string;
  path: string;
  /** Carried from static analysis: did the route appear auth-guarded? */
  guarded: boolean;
  /** True when the route's own path or guards carry admin-like evidence. */
  sensitive: boolean;
  /** Human-readable evidence for requesting this route. */
  why: string[];
}

export interface ProbePlan {
  targets: ProbeTarget[];
  skipped: SkippedRoute[];
}

const PARAM_RES = [/:([A-Za-z0-9_]+)/, /\{([^{}/]*)\}/, /<([^<>/]*)>/, /\[\[?(?:\.\.\.)?[^[\]/]*\]\]?/];
const PATTERN_CHARS = /[*()?+[\]\\]/;

export class EndpointMapper {
  static plan(routes: Route[]): ProbePlan {
    const seen = new Set<string>();
    const targets: ProbeTarget[] = [];
    const skipped: SkippedRoute[] = [];

    for (const r of routes) {
      const upper = r.method.toUpperCase();
      const method = upper === 'ALL' ? 'GET' : upper;
      const key = `${method} ${r.path}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const skip = (reason: string) => skipped.push({ method, path: r.path, reason });
      if (method !== 'GET') {
        skip('non-GET route: the scanner never mutates data');
        continue;
      }
      const unusable = EndpointMapper.unrequestable(r.path);
      if (unusable) {
        skip(unusable);
        continue;
      }

      const evidence = adminEvidence(r);
      targets.push({
        method,
        path: r.path,
        guarded: r.guarded,
        sensitive: evidence.length > 0,
        why: [
          r.source === 'openapi'
            ? `declared in OpenAPI/Swagger file ${r.file}`
            : `discovered at ${r.file}${r.line ? `:${r.line}` : ''}`,
          ...(r.specFiles?.length ? [`also declared in ${r.specFiles.join(', ')}`] : []),
          r.source === 'openapi'
            ? r.guarded
              ? 'requires auth per the spec'
              : 'no auth required per the spec'
            : r.guarded
              ? 'guarded in code'
              : 'unguarded in code',
          ...evidence,
        ],
      });
    }
    return { targets, skipped };
  }

  /** Reason a discovered path cannot be requested verbatim, or null if it can. */
  static unrequestable(path: string): string | null {
    if (!path.startsWith('/')) return `path "${path}" is not an absolute URL path`;
    for (const re of PARAM_RES) {
      const m = re.exec(path);
      if (m) {
        return `needs a value for path parameter "${m[0]}" that the scan cannot supply (values are never invented)`;
      }
    }
    if (PATTERN_CHARS.test(path)) {
      return 'path is a pattern or wildcard, not a concrete URL (the scan never invents a concrete path)';
    }
    return null;
  }
}
