/**
 * Shared contracts for the active security engine (Phase 5).
 *
 * An active scan replays a real, authenticated request with a tampered identity
 * (a swapped id, a different tenant, an escalated role) to prove whether the
 * target actually enforces access control. These types describe a request we
 * can manipulate without sending anything — the consented runner does the I/O.
 */
export interface HttpRequestSpec {
  method: string;
  /** URL path, may embed ids as segments (e.g. /users/123). */
  path: string;
  query?: Record<string, string | number>;
  headers?: Record<string, string>;
  /** Parsed JSON body (object) when present. */
  body?: unknown;
}

export type InjectionCategory = 'object-id' | 'tenant-id';

/** A spot in a request where an identity-bearing value can be swapped. */
export interface InjectionPoint {
  location: 'path' | 'query' | 'body';
  category: InjectionCategory;
  /** Addressing within the location: query key, body dotted-path, or path index. */
  field: string;
  /** The current value at that spot. */
  value: string | number;
  /** Human-readable label for reports. */
  label: string;
}
