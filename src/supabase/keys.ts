/**
 * Pure helpers to classify Supabase keys and URLs. No network.
 *
 * Supabase has two key families:
 *   - legacy JWT keys: `anon` and `service_role`, distinguished by the `role`
 *     claim (and usually carrying the project `ref` claim);
 *   - new API keys: `sb_publishable_…` (public, like anon) and `sb_secret_…`
 *     (privileged, like service_role).
 */
import { decodeJwt } from '../active/jwt';

export type KeyKind = 'anon' | 'service_role' | 'other-jwt' | 'unknown';

export interface KeyInfo {
  kind: KeyKind;
  /** Project ref from the JWT `ref` claim, when present. */
  ref?: string;
}

export const SB_SECRET_RE = /\bsb_secret_[A-Za-z0-9_-]{10,200}/;
export const SB_PUBLISHABLE_RE = /\bsb_publishable_[A-Za-z0-9_-]{10,200}/;
export const JWT_RE = /\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}/g;

export function classifyKey(key: string | undefined): KeyInfo {
  if (!key) return { kind: 'unknown' };
  const k = key.trim();
  if (/^sb_secret_/.test(k)) return { kind: 'service_role' };
  if (/^sb_publishable_/.test(k)) return { kind: 'anon' };
  const d = decodeJwt(k);
  if (!d) return { kind: 'unknown' };
  const role = d.payload.role;
  const ref = typeof d.payload.ref === 'string' ? d.payload.ref : undefined;
  if (role === 'service_role') return { kind: 'service_role', ref };
  if (role === 'anon') return { kind: 'anon', ref };
  return { kind: 'other-jwt', ref };
}

/** Project ref from a hosted Supabase URL (`https://<ref>.supabase.co`), or undefined. */
export function projectRefFromUrl(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  try {
    const host = new URL(raw).hostname.toLowerCase();
    const m = /^([a-z0-9]{10,40})\.supabase\.(?:co|in)$/.exec(host);
    return m ? m[1] : undefined;
  } catch {
    return undefined;
  }
}

/** Normalize a project URL to its origin (drops any /rest/v1 suffix). */
export function normalizeProjectUrl(raw: string): string {
  return new URL(raw.trim()).origin;
}
