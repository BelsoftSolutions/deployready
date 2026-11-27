/**
 * Ownership gate for live Supabase probes. Anon keys are public, so holding one
 * proves nothing: DeployReady must not become a scanner for other people's apps.
 *
 * Live probes are allowed ONLY when:
 *   (a) the project URL is loopback (a local `supabase start`), or
 *   (b) the user proves ownership of THAT project with
 *       - a service_role / sb_secret key that actually works for that URL
 *         (an admin-only endpoint answers 200), and whose `ref` claim, when
 *         present, matches the URL's project ref; or
 *       - a Supabase access token whose Management API project list contains
 *         the URL's project ref.
 * Otherwise the caller refuses with `reason`.
 */
import { SupabaseHttp, isLoopbackUrl, type Transport } from './http';
import { classifyKey, projectRefFromUrl } from './keys';

export type OwnershipMode = 'local' | 'service-role' | 'access-token';

export interface OwnershipResult {
  allowed: boolean;
  mode?: OwnershipMode;
  /** Human-readable reason (never contains a secret). */
  reason: string;
}

export interface OwnershipInput {
  url: string;
  serviceKey?: string;
  accessToken?: string;
}

export interface GuardDeps {
  /** Client bound to the project URL. */
  project: SupabaseHttp;
  /** Factory for a Management API client (only built when a token is given). */
  managementTransport?: Transport;
  minIntervalMs?: number;
}

export const MANAGEMENT_ORIGIN = 'https://api.supabase.com';

const REFUSAL =
  'Live Supabase checks only run against a project you prove you own: a local project (loopback URL, e.g. http://127.0.0.1:54321), ' +
  'or a hosted project with SUPABASE_SERVICE_ROLE_KEY (validated against that project) or SUPABASE_ACCESS_TOKEN (its project list must include that project). ' +
  'An anon key is public and is not proof of ownership.';

export async function checkOwnership(input: OwnershipInput, deps: GuardDeps): Promise<OwnershipResult> {
  if (isLoopbackUrl(input.url)) {
    return { allowed: true, mode: 'local', reason: 'Local Supabase project (loopback URL).' };
  }
  const ref = projectRefFromUrl(input.url);
  const failures: string[] = [];

  if (input.serviceKey) {
    const info = classifyKey(input.serviceKey);
    if (info.kind !== 'service_role') {
      failures.push('the provided service key is not a service_role / sb_secret key');
    } else if (info.ref && ref && info.ref !== ref) {
      failures.push('the service key belongs to a different project than the URL');
    } else {
      // Admin-only endpoint: only a working service key for THIS project gets 200.
      // The body (one user record) is discarded unread.
      const res = await deps.project.request({
        method: 'GET',
        path: '/auth/v1/admin/users',
        query: { page: 1, per_page: 1 },
        headers: { apikey: input.serviceKey, Authorization: `Bearer ${input.serviceKey}` },
      });
      if (res.status === 200) {
        return { allowed: true, mode: 'service-role', reason: 'Service key validated against this project.' };
      }
      failures.push(`the service key was rejected by this project (HTTP ${res.status})`);
    }
  }

  if (input.accessToken) {
    if (!ref) {
      failures.push('an access token can only prove ownership of a <ref>.supabase.co URL');
    } else {
      const mgmt = new SupabaseHttp({
        origin: MANAGEMENT_ORIGIN,
        transport: deps.managementTransport,
        minIntervalMs: deps.minIntervalMs,
        maxRequests: 5,
      });
      const res = await mgmt.request({
        method: 'GET',
        path: '/v1/projects',
        headers: { Authorization: `Bearer ${input.accessToken}` },
      });
      if (res.status === 200 && projectListIncludes(res.bodyText, ref)) {
        return { allowed: true, mode: 'access-token', reason: 'Access token lists this project.' };
      }
      failures.push(
        res.status === 200
          ? 'the access token does not list this project'
          : `the Management API rejected the access token (HTTP ${res.status})`,
      );
    }
  }

  const why = failures.length ? ` Not proven: ${failures.join('; ')}.` : '';
  return { allowed: false, reason: `${REFUSAL}${why}` };
}

function projectListIncludes(body: string, ref: string): boolean {
  try {
    const list = JSON.parse(body) as unknown;
    if (!Array.isArray(list)) return false;
    return list.some((p) => {
      const o = p as Record<string, unknown>;
      return o && (o.id === ref || o.ref === ref);
    });
  } catch {
    return false;
  }
}
