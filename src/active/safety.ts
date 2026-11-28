/**
 * Safety levels for the active scan (directive §7).
 *
 *   passive            no active request is sent at all (the plan can still be previewed)
 *   read-only          DEFAULT for --active: GET probes only; routes on the `unsafeRoutes`
 *                      denylist and routes whose path suggests a side effect (logout,
 *                      delete, send, pay, charge, export, webhook, reset, ...) are skipped,
 *                      because a GET is never assumed to be side-effect-free
 *   controlled-active  opt-in: also the unauthenticated DELETE/PATCH probe aimed at a record
 *                      id that cannot exist (loopback only)
 *   stateful           opt-in: probes that may change state; refused unless the config
 *                      declares the target disposable (`disposableEnvironment: true`) AND
 *                      the target is loopback or a host you declared you own. At this level
 *                      side-effect-looking GET routes are no longer skipped (the denylist
 *                      still is).
 *
 * Pure helpers; the Orchestrator applies them before anything is sent.
 */
import type { ActiveConfigSection, AppConfig } from '../types';
import { assertActiveTarget } from './scope';

import type { SafetyLevel } from '../types';

export type { SafetyLevel };

export const SAFETY_LEVELS: readonly SafetyLevel[] = ['passive', 'read-only', 'controlled-active', 'stateful'];
export const DEFAULT_SAFETY_LEVEL: SafetyLevel = 'read-only';
export const DEFAULT_MAX_REQUESTS = 200;

const RANK: Record<SafetyLevel, number> = { passive: 0, 'read-only': 1, 'controlled-active': 2, stateful: 3 };

export function atLeast(level: SafetyLevel, min: SafetyLevel): boolean {
  return RANK[level] >= RANK[min];
}

export function parseSafetyLevel(value: unknown): SafetyLevel {
  if (value === undefined || value === null || value === '') return DEFAULT_SAFETY_LEVEL;
  const v = String(value).trim().toLowerCase();
  if ((SAFETY_LEVELS as readonly string[]).includes(v)) return v as SafetyLevel;
  throw new Error(`Unknown safety level "${String(value)}". Use one of: ${SAFETY_LEVELS.join(', ')}.`);
}

export interface ActivePolicy {
  safetyLevel: SafetyLevel;
  unsafeRoutes: string[];
  ignoredFields: string[];
  publicRoutes: string[];
  maxRequests: number;
  disposableEnvironment: boolean;
}

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim() !== '') : []);

/** Merge config + CLI into one policy. The CLI level wins over the config's. Throws on an invalid level. */
export function resolveActivePolicy(config: Partial<AppConfig> | undefined, cli: { safetyLevel?: string } = {}): ActivePolicy {
  const section = (config?.active ?? {}) as ActiveConfigSection;
  const top = (config ?? {}) as { unsafeRoutes?: unknown; disposableEnvironment?: unknown };
  const max = Number(section.maxRequests);
  return {
    safetyLevel: parseSafetyLevel(cli.safetyLevel ?? section.safetyLevel),
    unsafeRoutes: [...strings(section.unsafeRoutes), ...strings(top.unsafeRoutes)],
    ignoredFields: strings(section.ignoredFields),
    publicRoutes: strings(section.publicRoutes),
    maxRequests: Number.isFinite(max) && max > 0 ? Math.floor(max) : DEFAULT_MAX_REQUESTS,
    disposableEnvironment: section.disposableEnvironment === true || top.disposableEnvironment === true,
  };
}

/**
 * Refuse a level the target does not qualify for. Stateful needs an explicit
 * `disposableEnvironment: true` AND a loopback or declared-owned host.
 */
export function assertSafetyAllowed(policy: ActivePolicy, baseUrl: string, ownedHosts: readonly string[]): void {
  if (policy.safetyLevel !== 'stateful') return;
  if (!policy.disposableEnvironment) {
    throw new Error(
      'Refusing the "stateful" safety level: it may change data, so the config must declare the target disposable ("active": { "disposableEnvironment": true }).',
    );
  }
  try {
    assertActiveTarget(baseUrl, ownedHosts);
  } catch (err) {
    throw new Error(`Refusing the "stateful" safety level: ${(err as Error).message}`);
  }
}

/** Path words that suggest a GET may still change state or trigger an action. */
const SIDE_EFFECT_WORDS = new Set([
  'logout', 'signout', 'logoff', 'delete', 'remove', 'destroy', 'purge', 'send', 'pay', 'payout', 'charge', 'checkout',
  'purchase', 'refund', 'transfer', 'export', 'webhook', 'webhooks', 'callback', 'reset', 'unsubscribe', 'cancel',
  'revoke', 'trigger', 'execute', 'invite', 'impersonate', 'approve', 'deploy', 'publish',
]);
const SIDE_EFFECT_PHRASES = /(?:^|_)(?:sign_out|log_out|log_off)(?:_|$)/;

function pathWords(path: string): string[] {
  return path
    .split('/')
    .flatMap((seg) => seg.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/))
    .filter(Boolean);
}

/** Why a route path looks like it has side effects, or null. */
export function sideEffectReason(path: string): string | null {
  const words = pathWords(path);
  const hit = words.find((w) => SIDE_EFFECT_WORDS.has(w));
  if (hit) return `path suggests a side effect ("${hit}"), and a GET is never assumed to be side-effect-free`;
  if (SIDE_EFFECT_PHRASES.test(words.join('_'))) return 'path suggests a side effect (sign-out), and a GET is never assumed to be side-effect-free';
  return null;
}

function globToRe(glob: string): RegExp {
  return new RegExp(`^${glob.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`, 'i');
}

/** The first pattern that matches `method path` (or any of `paths`), or null. */
export function matchRoutePattern(patterns: readonly string[], method: string, ...paths: string[]): string | null {
  for (const raw of patterns) {
    const p = raw.trim();
    const m = /^([A-Za-z]+)\s+(\S+)$/.exec(p);
    const wantMethod = m ? m[1]!.toUpperCase() : null;
    const re = globToRe(m ? m[2]! : p);
    if (wantMethod && wantMethod !== method.toUpperCase()) continue;
    if (paths.some((path) => re.test(path))) return raw;
  }
  return null;
}

/** Skip reason for an active request at this level, or null when it may be sent. */
export function routeSkipReason(level: SafetyLevel, method: string, routePath: string, unsafeRoutes: readonly string[], concretePath = routePath): string | null {
  if (level === 'passive') return 'safety level "passive" sends no active requests';
  const denied = matchRoutePattern(unsafeRoutes, method, routePath, concretePath);
  if (denied) return `listed in unsafeRoutes ("${denied}")`;
  if (!atLeast(level, 'stateful')) {
    const se = sideEffectReason(routePath);
    if (se) return `${se}; skipped at safety level "${level}" (only "stateful", on a disposable target, sends it)`;
  }
  return null;
}

/** The unauthenticated DELETE/PATCH probe needs controlled-active or higher. */
export function allowsMutationProbes(level: SafetyLevel): boolean {
  return atLeast(level, 'controlled-active');
}

/** Thrown by the transport when the run's request budget is used up. */
export class ActiveBudgetError extends Error {
  constructor(max: number) {
    super(`Active request budget of ${max} used up; no further requests were sent.`);
    this.name = 'ActiveBudgetError';
  }
}
