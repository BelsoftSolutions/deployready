/**
 * Re-runs the check that produced a finding to confirm whether it's actually
 * resolved. Used after applying a fix and via the `verify` command.
 *
 * - static findings: re-run the static scan and look for the same rule+file
 *   (matched on the redacted evidence snippet when available, so fixing one of
 *   several issues in a file is detected precisely).
 * - dynamic findings: re-probe the live app and look for the same rule+endpoint.
 *   Requires the app to still be running (and usually restarted to pick up code
 *   changes) — otherwise we report "unknown".
 * - ai findings: inferred, not mechanically checkable → "unknown".
 */
import { VulnerabilityDetector } from '../analysis/VulnerabilityDetector';
import { DynamicTester } from '../dynamic/DynamicTester';
import { assertLoopback } from '../dynamic/httpClient';
import { LocalhostDetector } from '../dynamic/LocalhostDetector';
import type { Finding, Route } from '../types';

export type VerifyStatus = 'fixed' | 'still-present' | 'unknown';

export interface VerifyResult {
  status: VerifyStatus;
  detail?: string;
}

export interface VerifyContext {
  target: string;
  dynamic?: { baseUrl: string; routes: Route[] };
}

export class Verifier {
  static async verify(finding: Finding, ctx: VerifyContext): Promise<VerifyResult> {
    if (finding.source === 'static') return Verifier.verifyStatic(finding, ctx);
    if (finding.source === 'dynamic') return Verifier.verifyDynamic(finding, ctx);
    return { status: 'unknown', detail: 'AI-inferred finding — re-run `ai` or `scan` to re-check.' };
  }

  private static async verifyStatic(finding: Finding, ctx: VerifyContext): Promise<VerifyResult> {
    let fresh: Finding[];
    try {
      fresh = await VulnerabilityDetector.scan(ctx.target);
    } catch (err) {
      return { status: 'unknown', detail: (err as Error).message };
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
      return { status: 'unknown', detail: 'No running app in this session — start it and run `dynamic` to re-check.' };
    }
    const { baseUrl, routes } = ctx.dynamic;
    try {
      assertLoopback(baseUrl);
    } catch {
      return { status: 'unknown' };
    }
    // Confirm the app is still up before re-probing.
    const port = Number(new URL(baseUrl).port) || 80;
    const app = await LocalhostDetector.find([port]);
    if (!app) {
      return { status: 'unknown', detail: 'The app is no longer reachable — restart it to verify dynamic fixes.' };
    }

    try {
      const results = await DynamicTester.run(baseUrl, routes, {
        aggressive: finding.rule === 'missing-rate-limit',
      });
      const present = results.findings.some(
        (f) => f.rule === finding.rule && f.endpoint === finding.endpoint,
      );
      return present
        ? { status: 'still-present', detail: 'Endpoint still fails this check (restart the app if you just edited code).' }
        : { status: 'fixed' };
    } catch (err) {
      return { status: 'unknown', detail: (err as Error).message };
    }
  }
}
