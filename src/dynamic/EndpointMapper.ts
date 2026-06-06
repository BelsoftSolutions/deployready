/**
 * Build the list of endpoints to probe by combining statically-discovered
 * routes with a small set of common live paths. Path params (:id, {id}) are
 * filled with a benign sample value.
 */
import type { Route } from '../types';

export interface ProbeTarget {
  method: string;
  path: string;
  /** Carried from static analysis: did the route appear auth-guarded? */
  guarded: boolean;
  /** True if this path is a well-known sensitive/admin route. */
  sensitive: boolean;
}

const COMMON_PATHS = ['/', '/health', '/api', '/api/health', '/status', '/metrics'];
const SENSITIVE_PATHS = ['/admin', '/api/admin', '/.env', '/debug', '/actuator', '/api/users'];

export class EndpointMapper {
  static build(routes: Route[]): ProbeTarget[] {
    const seen = new Set<string>();
    const targets: ProbeTarget[] = [];

    const add = (t: ProbeTarget) => {
      const key = `${t.method} ${t.path}`;
      if (seen.has(key)) return;
      seen.add(key);
      targets.push(t);
    };

    for (const r of routes) {
      add({
        method: r.method === 'ALL' ? 'GET' : r.method,
        path: EndpointMapper.concretePath(r.path),
        guarded: r.guarded,
        sensitive: SENSITIVE_PATHS.some((p) => r.path.startsWith(p)),
      });
    }

    for (const p of COMMON_PATHS) add({ method: 'GET', path: p, guarded: false, sensitive: false });
    for (const p of SENSITIVE_PATHS) add({ method: 'GET', path: p, guarded: true, sensitive: true });

    return targets;
  }

  /** Replace :id / {id} / <id> params with a safe sample value. */
  private static concretePath(routePath: string): string {
    return routePath
      .replace(/:([A-Za-z0-9_]+)/g, '1')
      .replace(/\{([A-Za-z0-9_]+)\}/g, '1')
      .replace(/<[^>]+>/g, '1');
  }
}
