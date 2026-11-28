/**
 * Re-check one authorization-matrix finding (used by the Verifier): re-run the
 * matrix for that route only, with the identities and policy of the project's
 * `.deployready.json` (credentials from the environment / saved sessions, never
 * from tool arguments).
 *
 *   still-present  the same rule fires again on the route (fresh proof attached)
 *   fixed          no violation, and at least one cell on the route is
 *                  denied-as-expected (the attack is refused while the owner's
 *                  own request still works: verified-denied needs that control)
 *   inconclusive   anything else, with why
 */
import { ConfigManager } from '../config/ConfigManager';
import type { Finding, Proof, Route } from '../types';
import { runAuthz } from './authzEngine';
import { createActiveHttpAdapter } from './httpAdapter';
import { disposeIdentities, resolveIdentities } from './identities';
import { authzSettings, loadProjectActiveConfig, mergeActiveConfig } from './projectConfig';
import type { HttpFn } from './runner';
import { assertSafetyAllowed, resolveActivePolicy } from './safety';
import { parseOwnedHosts } from './scope';

export interface AuthzVerifyContext {
  baseUrl: string;
  routes: Route[];
  ownedHosts?: string[];
  /** Injected transport (tests). */
  http?: HttpFn;
  env?: NodeJS.ProcessEnv;
}

export interface AuthzVerifyResult {
  status: 'fixed' | 'still-present' | 'inconclusive';
  detail?: string;
  proof?: Proof;
}

const inconclusive = (detail: string): AuthzVerifyResult => ({ status: 'inconclusive', detail });

export async function verifyAuthzFinding(finding: Finding, target: string, ctx: AuthzVerifyContext | undefined): Promise<AuthzVerifyResult> {
  if (!ctx) return inconclusive('This is an authorization-matrix finding; re-checking it needs the running app (start it and re-run `deployready analyze --active`).');
  if (!finding.endpoint) return inconclusive('The finding has no route to re-check.');
  const project = await loadProjectActiveConfig(target);
  let config;
  try {
    config = mergeActiveConfig(await ConfigManager.load(), project);
  } catch (err) {
    return inconclusive((err as Error).message);
  }
  const settings = authzSettings(config.active as Record<string, unknown> | undefined, project.file ?? 'config');
  if (!settings.policy || settings.policy.draft) return inconclusive('No reviewed (non-draft) active.policy in .deployready.json, so the matrix cannot be re-run.');
  let owned: string[];
  let level;
  try {
    level = resolveActivePolicy(config);
    owned = parseOwnedHosts([...(ctx.ownedHosts ?? []), ...(Array.isArray(config.ownedTargets) ? config.ownedTargets : [])]);
    assertSafetyAllowed(level, ctx.baseUrl, owned);
  } catch (err) {
    return inconclusive((err as Error).message);
  }
  const identities = await resolveIdentities(settings.identities, { env: ctx.env, baseUrl: ctx.baseUrl, projectPath: target, ownedHosts: owned });
  try {
    const http = ctx.http ?? createActiveHttpAdapter({ baseUrl: ctx.baseUrl, ownedHosts: owned, maxRequests: level.maxRequests });
    const { matrix, findings } = await runAuthz(
      {
        policy: settings.policy,
        identities,
        routes: ctx.routes,
        safetyLevel: level.safetyLevel,
        unsafeRoutes: level.unsafeRoutes,
        ignoredFields: level.ignoredFields,
        maxRequests: level.maxRequests,
        baseUrl: ctx.baseUrl,
        onlyRoute: finding.endpoint,
      },
      http,
    );
    const again = findings.find((f) => f.rule === finding.rule && f.endpoint === finding.endpoint);
    if (again) return { status: 'still-present', detail: again.evidence ?? again.description, ...(again.proof ? { proof: again.proof } : {}) };
    if (!matrix.cells.length) return inconclusive(`${finding.endpoint} is no longer in the policy, so it could not be re-checked.`);
    const denied = matrix.cells.filter((c) => c.verdict === 'denied-as-expected').length;
    const open = matrix.cells.filter((c) => c.verdict === 'inconclusive' || c.verdict === 'untested');
    if (denied > 0) {
      return { status: 'fixed', detail: `${denied} cell(s) on ${finding.endpoint} are now denied as expected${open.length ? `; ${open.length} other cell(s) were not conclusive` : ''}.` };
    }
    return inconclusive(`No cell on ${finding.endpoint} was conclusive: ${open.slice(0, 3).map((c) => `${c.identity}: ${c.reason}`).join('; ') || 'nothing ran'}.`);
  } finally {
    await disposeIdentities(identities);
  }
}
