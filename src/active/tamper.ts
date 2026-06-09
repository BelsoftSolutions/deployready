/**
 * Discover and rewrite identity-bearing values in a request (Phase 5b).
 *
 * Pure, no network. `findInjectionPoints` locates object ids (BOLA/IDOR) and
 * tenant ids (multi-tenant isolation) in the path, query, and JSON body;
 * `applyInjection` returns a NEW spec with one of them swapped. The runner uses
 * a real second-identity value and checks the response via `accessControl`.
 */
import type { HttpRequestSpec, InjectionCategory, InjectionPoint } from './types';

/** Keys that denote a tenant/organization boundary. */
const TENANT_KEY_RE = /^(?:org|organization|tenant|team|company|workspace)(?:[-_]?id)?$/i;
/** Keys that denote an object/owner id. */
const OBJECT_ID_KEY_RE = /(?:^id$|_id$|^uid$|Id$)/;

/** A value that looks like an id worth swapping: number, numeric string, or UUID. */
function looksLikeId(value: unknown): value is string | number {
  if (typeof value === 'number') return true;
  if (typeof value !== 'string') return false;
  return /^\d+$/.test(value) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

/** Categorize a key name, or null if it isn't identity-bearing. */
function categorize(key: string): InjectionCategory | null {
  if (TENANT_KEY_RE.test(key)) return 'tenant-id';
  if (OBJECT_ID_KEY_RE.test(key)) return 'object-id';
  return null;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function findInjectionPoints(spec: HttpRequestSpec): InjectionPoint[] {
  const points: InjectionPoint[] = [];

  // Path: any segment that looks like a bare id is an object id.
  const parts = spec.path.split('/');
  parts.forEach((seg, i) => {
    if (seg && looksLikeId(seg)) {
      points.push({ location: 'path', category: 'object-id', field: String(i), value: seg, label: `path segment "${seg}"` });
    }
  });

  // Query: classify by key name.
  for (const [key, value] of Object.entries(spec.query ?? {})) {
    const category = categorize(key);
    if (category) points.push({ location: 'query', category, field: key, value, label: `query.${key}` });
  }

  // Body: walk a JSON object, classify by key name, address via dotted path.
  if (isPlainObject(spec.body)) {
    walkBody(spec.body, '', points);
  }

  return points;
}

function walkBody(obj: Record<string, unknown>, prefix: string, out: InjectionPoint[]): void {
  for (const [key, value] of Object.entries(obj)) {
    const dotted = prefix ? `${prefix}.${key}` : key;
    if (isPlainObject(value)) {
      walkBody(value, dotted, out);
      continue;
    }
    const category = categorize(key);
    if (category && (typeof value === 'string' || typeof value === 'number')) {
      out.push({ location: 'body', category, field: dotted, value, label: `body.${dotted}` });
    }
  }
}

/** Return a new spec with `point` set to `newValue`. Does not mutate `spec`. */
export function applyInjection(spec: HttpRequestSpec, point: InjectionPoint, newValue: string | number): HttpRequestSpec {
  if (point.location === 'path') {
    const parts = spec.path.split('/');
    parts[Number(point.field)] = String(newValue);
    return { ...spec, path: parts.join('/') };
  }
  if (point.location === 'query') {
    return { ...spec, query: { ...(spec.query ?? {}), [point.field]: newValue } };
  }
  // body — clone and set by dotted path.
  const body = JSON.parse(JSON.stringify(spec.body ?? {})) as Record<string, unknown>;
  const keys = point.field.split('.');
  let cursor: Record<string, unknown> = body;
  for (let i = 0; i < keys.length - 1; i++) cursor = cursor[keys[i]!] as Record<string, unknown>;
  cursor[keys[keys.length - 1]!] = newValue;
  return { ...spec, body };
}
