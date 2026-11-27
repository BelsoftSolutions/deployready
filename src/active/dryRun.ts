/**
 * `--dry-run` for the active scan: list every request the scan WOULD send,
 * without sending any. Pure, no network.
 *
 * Conditional requests (the forged-token checks, the anonymous control, the
 * escalation variants) are listed with the condition that triggers them, and
 * the total is an upper bound, capped by the request budget.
 */
import { absoluteUrl } from '../dynamic/proof';
import { findInjectionPoints, applyInjection } from './tamper';
import type { HttpRequestSpec } from './types';
import type { MutationTarget } from './mutationProbe';
import type { SkippedRoute } from '../types';
import type { SafetyLevel } from './safety';

export interface DryRunInput {
  baseUrl?: string;
  safetyLevel: SafetyLevel;
  requests: HttpRequestSpec[];
  /** Claims of the second identity ($TOKEN_B), when given. */
  tokenBClaims?: Record<string, unknown> | null;
  mutationTargets?: MutationTarget[];
  skipped?: SkippedRoute[];
  maxRequests: number;
  ownerBaselineCount?: number;
}

export interface DryRunPlan {
  lines: string[];
  /** Upper bound on requests the real run could send (before the budget). */
  upperBound: number;
}

function qs(req: HttpRequestSpec): string {
  const q = req.query ?? {};
  const keys = Object.keys(q);
  return keys.length ? `?${new URLSearchParams(keys.map((k): [string, string] => [k, String(q[k])])).toString()}` : '';
}

function foreignFor(category: 'object-id' | 'tenant-id', claims: Record<string, unknown>): string | number | null {
  const c =
    category === 'tenant-id'
      ? [claims.org_id, claims.organization_id, claims.tenant_id, claims.tenant, claims.workspace_id]
      : [claims.sub, claims.user_id, claims.uid, claims.id];
  for (const v of c) if (typeof v === 'string' || typeof v === 'number') return v;
  return null;
}

export function previewActivePlan(input: DryRunInput): DryRunPlan {
  const lines: string[] = [];
  const url = (req: HttpRequestSpec) => absoluteUrl(input.baseUrl, req.path + qs(req));
  const owners = Math.max(1, input.ownerBaselineCount ?? 2);
  let n = 0;
  const add = (count: number, text: string) => {
    n += count;
    lines.push(`  ${text}`);
  };

  lines.push(`Active scan dry run — safety level "${input.safetyLevel}". Nothing below is sent.`);
  if (input.safetyLevel === 'passive') lines.push('Safety level "passive": a real run would send none of these either.');
  for (const req of input.requests) {
    lines.push(`${req.method} ${req.path}`);
    add(1, `${req.method} ${url(req)}  as $TOKEN (baseline)`);
    add(1, `${req.method} ${url(req)}  without credentials (control for the forged-token check, first reachable route only)`);
    add(2, `${req.method} ${url(req)}  with forged copies of $TOKEN (alg:none; or admin-role variants if the baseline is 403)`);
    const points = input.tokenBClaims ? findInjectionPoints(req) : [];
    if (points.length) add(1, `${req.method} ${url(req)}  as $TOKEN again (second own baseline, learns volatile fields)`);
    for (const p of points) {
      const foreign = foreignFor(p.category, input.tokenBClaims!);
      if (foreign === null || String(foreign) === String(p.value)) continue;
      const t = applyInjection(req, p, foreign);
      add(1, `${t.method} ${url(t)}  as $TOKEN (${p.label} swapped to $TOKEN_B's value)`);
      add(owners, `${t.method} ${url(t)}  as $TOKEN_B ×${owners} (owner baselines)`);
      add(1, `${t.method} ${url(t)}  without credentials (only if owner data came back)`);
    }
  }
  if (!input.tokenBClaims && input.requests.length) lines.push('No --token-b: cross-identity (IDOR / tenant) requests are not planned.');
  if (input.mutationTargets?.length) {
    lines.push('Unauthenticated write-route probe (controlled-active, loopback only):');
    for (const t of input.mutationTargets) add(1, `${t.method} ${absoluteUrl(input.baseUrl, t.path)}  without credentials, no body (non-existent id)`);
    add(1, `<same method> ${absoluteUrl(input.baseUrl, '/__deployready_probe_<random>__')}  control, only if a probe answers 2xx`);
  }
  if (input.skipped?.length) {
    lines.push('Skipped:');
    for (const s of input.skipped) lines.push(`  ${s.method} ${s.path}: ${s.reason}`);
  }
  lines.push(`At most ${Math.min(n, input.maxRequests)} request(s) (upper bound ${n}; request budget ${input.maxRequests}).`);
  return { lines, upperBound: n };
}
