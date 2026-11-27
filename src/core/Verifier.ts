/**
 * Re-runs the check that produced a finding to confirm whether it's actually
 * resolved. Used after applying a fix and via the `verify` command.
 *
 * Statuses: `fixed` | `still-present` | `inconclusive`. "Fixed" is a claim that
 * needs proof, so anything short of proof is `inconclusive` with a reason that
 * says what was missing:
 *
 * - static findings: re-run the static scan and look for the same rule+file
 *   (matched on the redacted evidence snippet when available, so fixing one of
 *   several issues in a file is detected precisely).
 * - dynamic findings: re-probe the live app and look for the same rule+endpoint.
 *   A failed or unanswered request never proves a fix: `fixed` needs the
 *   original trigger to fail (the endpoint answered without the issue) AND a
 *   control request to still succeed (some route still answers 2xx), so an app
 *   that is down or erroring is not mistaken for a fixed one.
 * - active findings (JWT / escalation / IDOR / tenant): re-run the active check
 *   on the same endpoint with the user's tokens. `fixed` needs the attack to be
 *   refused AND the legitimate request (your own token, or the owner's for
 *   IDOR/tenant) to still work. For IDOR/tenant "refused" means the semantic
 *   verdict is `verified-denied` (none of the owner's data in the body, whatever
 *   the status code), not merely a 401/403/404. Without tokens: inconclusive.
 * - ai findings: inferred, not mechanically checkable → inconclusive.
 */
import { VulnerabilityDetector } from '../analysis/VulnerabilityDetector';
import { DynamicTester } from '../dynamic/DynamicTester';
import { assertLoopback } from '../dynamic/httpClient';
import { LocalhostDetector } from '../dynamic/LocalhostDetector';
import { decodeJwt } from '../active/jwt';
import { planActiveRequests } from '../active/requestPlan';
import { createActiveHttpAdapter } from '../active/httpAdapter';
import { ACTIVE_RULES, runActiveScan, type ActiveObservation, type HttpFn } from '../active/runner';
import { MUTATION_RULE, planMutationProbes, runMutationProbes, type MutationObservation } from '../active/mutationProbe';
import type { Finding, Proof, Route } from '../types';

export type VerifyStatus = 'fixed' | 'still-present' | 'inconclusive';

export interface VerifyResult {
  status: VerifyStatus;
  detail?: string;
  /** Proof from the re-check, when the issue is still present. */
  proof?: Proof;
}

export interface VerifyContext {
  target: string;
  dynamic?: { baseUrl: string; routes: Route[] };
  /** Needed to re-check active findings: the same tokens the scan used. */
  active?: {
    baseUrl: string;
    routes: Route[];
    token: string;
    tokenB?: string;
    /** Non-loopback hosts the user explicitly confirmed they own. */
    ownedHosts?: string[];
    /** Injected transport (tests); defaults to the guarded real adapter. */
    http?: HttpFn;
  };
}

/**
 * Test identities for re-checking active findings come from the environment only
 * (DEPLOYREADY_TOKEN, DEPLOYREADY_TOKEN_B), never from tool arguments, so a token
 * is never typed into a chat or logged. Returns undefined when no token is set.
 */
export function tokensFromEnv(env: NodeJS.ProcessEnv = process.env): { token: string; tokenB?: string } | undefined {
  const token = env.DEPLOYREADY_TOKEN?.trim();
  if (!token) return undefined;
  const tokenB = env.DEPLOYREADY_TOKEN_B?.trim();
  return { token, ...(tokenB ? { tokenB } : {}) };
}

/** The `active` part of a VerifyContext, built from env tokens (undefined without a token or base URL). */
export function activeContextFromEnv(
  baseUrl: string | undefined,
  routes: Route[],
  env: NodeJS.ProcessEnv = process.env,
): VerifyContext['active'] | undefined {
  const tokens = tokensFromEnv(env);
  if (!tokens || !baseUrl) return undefined;
  return { baseUrl, routes, ...tokens };
}

const inconclusive = (detail: string): VerifyResult => ({ status: 'inconclusive', detail });

function is2xx(status: number | undefined): boolean {
  return status !== undefined && status >= 200 && status < 300;
}

function isDenied(status: number | undefined): boolean {
  return status === 401 || status === 403;
}

/** Rules whose trigger is "this route answered 2xx without credentials". */
const UNAUTH_ACCESS_RULES = new Set(['auth-bypass', 'exposed-admin-route']);

export class Verifier {
  static async verify(finding: Finding, ctx: VerifyContext): Promise<VerifyResult> {
    if (finding.source === 'static') return Verifier.verifyStatic(finding, ctx);
    if (finding.source === 'dynamic' && finding.rule === MUTATION_RULE) return Verifier.verifyMutation(finding, ctx);
    if (finding.source === 'dynamic' && ACTIVE_RULES.has(finding.rule)) return Verifier.verifyActive(finding, ctx);
    if (finding.source === 'dynamic') return Verifier.verifyDynamic(finding, ctx);
    return inconclusive('AI-inferred finding — re-run `ai` or `scan` to re-check.');
  }

  private static async verifyStatic(finding: Finding, ctx: VerifyContext): Promise<VerifyResult> {
    let fresh: Finding[];
    try {
      fresh = await VulnerabilityDetector.scan(ctx.target);
    } catch (err) {
      return inconclusive((err as Error).message);
    }
    const present = fresh.some(
      (f) =>
        f.rule === finding.rule &&
        f.file === finding.file &&
        (finding.evidence ? f.evidence === finding.evidence : true),
    );
    return present
      ? { status: 'still-present', detail: 'The same issue still appears in this file.' }
      : { status: 'fixed' };
  }

  private static async verifyDynamic(finding: Finding, ctx: VerifyContext): Promise<VerifyResult> {
    if (!ctx.dynamic) {
      return inconclusive('No running app in this session — start it and run `dynamic` to re-check.');
    }
    const { baseUrl, routes } = ctx.dynamic;
    if (routes.length === 0) {
      return inconclusive('No routes were discovered in the code, so there is nothing to re-check (DeployReady does not guess routes).');
    }
    try {
      assertLoopback(baseUrl);
    } catch (err) {
      return inconclusive(`${(err as Error).message} Nothing was re-checked.`);
    }
    // Confirm the app is still up before re-probing.
    const port = Number(new URL(baseUrl).port) || 80;
    const app = await LocalhostDetector.find([port]);
    if (!app) {
      return inconclusive('No local server is listening on that port any more — restart it to verify dynamic fixes.');
    }

    let results;
    try {
      results = await DynamicTester.run(baseUrl, routes, {
        aggressive: finding.rule === 'missing-rate-limit',
      });
    } catch (err) {
      return inconclusive((err as Error).message);
    }
    if (!results.probed?.length) {
      return inconclusive('None of the discovered routes can be requested, so this could not be re-checked.');
    }
    const same = results.findings.filter((f) => f.rule === finding.rule && f.endpoint === finding.endpoint);
    const reported = same.find((f) => !f.note);
    if (reported) {
      return {
        status: 'still-present',
        detail: 'Endpoint still fails this check (restart the app if you just edited code).',
        ...(reported.proof ? { proof: reported.proof } : {}),
      };
    }
    if (same.length) {
      return inconclusive(`The re-check could not run: ${same[0]!.title.toLowerCase()}.`);
    }

    // Trigger: the endpoint itself must have answered, and not with an error.
    const endpoints = results.endpoints ?? [];
    const answer = finding.endpoint ? endpoints.find((e) => e.path === finding.endpoint) : undefined;
    if (finding.endpoint) {
      if (answer?.status === undefined) {
        return inconclusive(`${finding.endpoint} did not answer the re-check; a request that fails is not proof of a fix.`);
      }
      if (answer.status >= 500) {
        return inconclusive(`${finding.endpoint} answered HTTP ${answer.status}; an error response is not proof of a fix.`);
      }
    }

    // Control: some request must still succeed, so a broken or locked-down app
    // is not mistaken for a fix. For unauthenticated-access rules the endpoint's
    // own 2xx would BE the issue, so the control has to be another route.
    const control = endpoints.find(
      (e) => is2xx(e.status) && (e.path !== finding.endpoint || !UNAUTH_ACCESS_RULES.has(finding.rule)),
    );
    if (!control) {
      return inconclusive(
        `${finding.endpoint ? `${finding.endpoint} answered HTTP ${answer!.status}, but no` : 'No'} control request succeeded (no route answered 2xx), so a fix cannot be told apart from an app that is down or rejecting everything.`,
      );
    }
    return {
      status: 'fixed',
      detail: `${finding.endpoint ? `${finding.endpoint} now answers HTTP ${answer!.status}` : 'The check no longer fires'}; control GET ${control.path} still answers HTTP ${control.status}.`,
    };
  }

  private static async verifyActive(finding: Finding, ctx: VerifyContext): Promise<VerifyResult> {
    const active = ctx.active;
    if (!active) {
      return inconclusive(
        'This is an active (token-based) finding and this session has no test token — set DEPLOYREADY_TOKEN (and DEPLOYREADY_TOKEN_B) in the environment, or re-run `deployready analyze --active --token … --token-b …`.',
      );
    }
    if (!finding.endpoint) return inconclusive('The finding has no endpoint to re-check.');
    const claims = decodeJwt(active.token)?.payload;
    if (!claims) return inconclusive('The test token is not a valid JWT, so the request could not be rebuilt.');
    const needsOwner = finding.rule === 'bola-idor' || finding.rule === 'tenant-isolation-broken';
    if (needsOwner && !active.tokenB) {
      return inconclusive(
        "Proving this fixed needs a control request from the resource's owner — set the second identity's token (DEPLOYREADY_TOKEN_B, or --token-b).",
      );
    }

    const requests = planActiveRequests(active.routes, claims).requests.filter((r) => r.path === finding.endpoint);
    if (requests.length === 0) {
      return inconclusive(`${finding.endpoint} is no longer among the routes your token can request, so it could not be re-checked.`);
    }

    let http: HttpFn;
    try {
      http = active.http ?? createActiveHttpAdapter({ baseUrl: active.baseUrl, ownedHosts: active.ownedHosts });
    } catch (err) {
      return inconclusive(`${(err as Error).message} Nothing was re-checked.`);
    }

    const seen: ActiveObservation[] = [];
    let findings: Finding[];
    try {
      findings = await runActiveScan(
        {
          token: active.token,
          tokenB: active.tokenB,
          requests,
          baseUrl: active.baseUrl,
          alwaysFetchOwnerControl: true,
          onObserve: (o) => seen.push(o),
        },
        http,
      );
    } catch (err) {
      return inconclusive(`The re-check request failed (${(err as Error).message}); a failed request is not proof of a fix.`);
    }

    const again = findings.find((f) => f.rule === finding.rule && f.endpoint === finding.endpoint);
    if (again) {
      return {
        status: 'still-present',
        detail: 'The same attack still succeeds (restart the app if you just edited code).',
        ...(again.proof ? { proof: again.proof } : {}),
      };
    }
    const baseline = seen.find((o) => o.kind === 'baseline' && o.endpoint === finding.endpoint);
    const baselineNote = baseline?.kind === 'baseline' ? ` (your token now gets HTTP ${baseline.status} there)` : '';
    return Verifier.judgeActive(finding, seen, baselineNote);
  }

  /** Re-send the anonymous DELETE/PATCH (non-existent id, loopback only). */
  private static async verifyMutation(finding: Finding, ctx: VerifyContext): Promise<VerifyResult> {
    const active = ctx.active;
    if (!active) {
      return inconclusive('Re-checking a write route needs the opted-in active scan — re-run `deployready analyze --active --token …`.');
    }
    try {
      assertLoopback(active.baseUrl);
    } catch {
      return inconclusive('Write routes are only re-probed on a loopback target. Nothing was sent.');
    }
    const targets = planMutationProbes(active.routes).targets.filter((t) => `${t.method} ${t.route}` === finding.endpoint);
    if (targets.length === 0) return inconclusive(`${finding.endpoint} is no longer a discovered route that can be probed safely.`);
    let http: HttpFn;
    try {
      http = active.http ?? createActiveHttpAdapter({ baseUrl: active.baseUrl });
    } catch (err) {
      return inconclusive(`${(err as Error).message} Nothing was re-checked.`);
    }
    const seen: MutationObservation[] = [];
    const again = await runMutationProbes(targets, http, { baseUrl: active.baseUrl, onObserve: (o) => seen.push(o) });
    if (again.length) {
      return { status: 'still-present', detail: 'The route still accepts the request without credentials.', ...(again[0]!.proof ? { proof: again[0]!.proof } : {}) };
    }
    const o = seen[0];
    if (o?.trigger === undefined) return inconclusive(`${finding.endpoint} did not answer; a failed request is not proof of a fix.`);
    if (isDenied(o.trigger)) {
      return { status: 'fixed', detail: `${finding.endpoint} without credentials now gets HTTP ${o.trigger} (an explicit auth refusal).` };
    }
    return inconclusive(`${finding.endpoint} without credentials got HTTP ${o.trigger}; only a 401/403 proves authentication is enforced.`);
  }

  /** Decide fixed vs inconclusive from what the active re-check observed. */
  private static judgeActive(finding: Finding, seen: ActiveObservation[], baselineNote: string): VerifyResult {
    const ep = finding.endpoint!;
    if (finding.rule === 'jwt-not-verified') {
      const o = seen.find((x): x is Extract<ActiveObservation, { kind: 'jwt' }> => x.kind === 'jwt' && x.endpoint === ep);
      if (!o) return inconclusive(`The forged-token test did not run on ${ep}${baselineNote}.`);
      if (o.trigger === undefined) {
        return inconclusive(
          `${ep} no longer rejects requests without a token (HTTP ${o.anonymousStatus}), so a forged token proves nothing there.`,
        );
      }
      if (!isDenied(o.trigger)) {
        return inconclusive(`The forged alg:none token got HTTP ${o.trigger}; only a 401/403 proves it was rejected.`);
      }
      if (!is2xx(o.control)) {
        return inconclusive(`The forged token was refused, but your real token also failed (HTTP ${o.control}) — no working control request.`);
      }
      return { status: 'fixed', detail: `Forged alg:none token now gets HTTP ${o.trigger}; your real token still gets HTTP ${o.control}.` };
    }

    if (finding.rule === 'privilege-escalation') {
      const o = seen.find((x): x is Extract<ActiveObservation, { kind: 'escalation' }> => x.kind === 'escalation' && x.endpoint === ep);
      if (!o) return inconclusive(`The escalation test only runs where your token gets 403, and it did not run on ${ep}${baselineNote}.`);
      if (o.trigger.length === 0) return inconclusive('No forged-role request could be sent.');
      const bad = o.trigger.find((s) => !isDenied(s));
      if (bad !== undefined) return inconclusive(`A forged-role token got HTTP ${bad}; only 401/403 proves it was rejected.`);
      return {
        status: 'fixed',
        detail: `Forged admin-role tokens now get HTTP ${o.trigger.join('/')}; your real token still gets its normal HTTP ${o.control}.`,
      };
    }

    // bola-idor / tenant-isolation-broken
    const tries = seen.filter(
      (x): x is Extract<ActiveObservation, { kind: 'cross' }> => x.kind === 'cross' && x.rule === finding.rule && x.endpoint === ep,
    );
    if (tries.length === 0) {
      const untested = seen.find((x): x is Extract<ActiveObservation, { kind: 'untested' }> => x.kind === 'untested' && x.endpoint === ep);
      return inconclusive(`No cross-identity request could be ${untested ? `sent for ${ep} (${untested.reason})` : `built for ${ep}${baselineNote}`}.`);
    }
    for (const t of tries) {
      if (t.verdict !== 'verified-denied') {
        return inconclusive(`Requesting ${t.tamperedPath} as the test user got HTTP ${t.trigger}, verdict ${t.verdict}: ${t.reason}`);
      }
      if (!is2xx(t.control)) {
        return inconclusive(
          `${t.tamperedPath} was refused for the test user, but the owner's own request ($TOKEN_B) also failed (HTTP ${t.control ?? 'not sent'}) — no working control request.`,
        );
      }
    }
    const t = tries[0]!;
    return {
      status: 'fixed',
      detail: `${t.tamperedPath} as the test user: ${t.outcome === 'denied' ? `HTTP ${t.trigger}` : 'own data only'}; the owner still gets HTTP ${t.control}.`,
    };
  }
}
