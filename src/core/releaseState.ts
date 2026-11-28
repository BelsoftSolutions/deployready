/**
 * Release state: a policy-driven verdict kept separate from the numeric score.
 *
 * The score only counts confirmed findings in the areas that ran, so 100 can coexist with an
 * unverified AI critical or with a scanner step that crashed. The release state looks at all four
 * dimensions (findings, coverage, confidence, verification) and never reads "ready" when:
 *   - a confirmed finding at a blockOn severity is open           -> not-ready
 *   - a mandatory area errored or did not run                     -> insufficient-evidence
 *   - an unverified/AI or suspected finding is at a blockOn severity,
 *     or any other area errored / a mandatory one is inconclusive -> review-required
 * Accepted baseline risks give ready-with-accepted-risks. "ready" from static evidence alone is
 * flagged as limited coverage.
 */
import { isNonScored, isNote, isUnverified } from '../analysis/ScoreCalculator';
import { coverageSummary } from './coverage';
import type { CoverageArea, Finding, ReleaseAssessment, ReleasePolicy, ReleaseState, ScanReport, Severity } from '../types';

export const RELEASE_STATES: ReleaseState[] = ['ready', 'ready-with-accepted-risks', 'review-required', 'not-ready', 'insufficient-evidence'];

/** Gate order, best to worst. insufficient-evidence is worst: nothing proves the release is safe. */
const RANK: Record<ReleaseState, number> = {
  ready: 0,
  'ready-with-accepted-risks': 1,
  'review-required': 2,
  'not-ready': 3,
  'insufficient-evidence': 4,
};

export const SCORE_DISCLAIMER = 'A score of 100 means no confirmed findings in the areas tested, not that the app is secure.';

export const DEFAULT_RELEASE_POLICY: ReleasePolicy = {
  blockOn: ['critical'],
  requireAreas: ['static', 'secrets'],
  treatUnverifiedCriticalAs: 'review-required',
};

const SEVERITIES: Severity[] = ['critical', 'warning', 'info'];
const AREA_NAMES = ['static', 'secrets', 'dependencies', 'engines', 'supabase-static', 'supabase-live', 'supabase-drift', 'firebase', 'dynamic', 'active', 'ai'];

/** Normalize a config value into a full policy. Invalid entries are dropped and reported, never fatal. */
export function parseReleasePolicy(raw: unknown): { policy: ReleasePolicy; warnings: string[] } {
  const warnings: string[] = [];
  const policy: ReleasePolicy = {
    blockOn: [...DEFAULT_RELEASE_POLICY.blockOn],
    requireAreas: [...DEFAULT_RELEASE_POLICY.requireAreas],
    treatUnverifiedCriticalAs: DEFAULT_RELEASE_POLICY.treatUnverifiedCriticalAs,
  };
  if (raw === undefined || raw === null) return { policy, warnings };
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    return { policy, warnings: ['releasePolicy must be an object; using the default policy.'] };
  }
  const r = raw as Record<string, unknown>;
  if (r.blockOn !== undefined) {
    const list = Array.isArray(r.blockOn) ? r.blockOn : [];
    const valid = list.filter((s): s is Severity => SEVERITIES.includes(s as Severity));
    if (!Array.isArray(r.blockOn) || valid.length !== list.length) {
      warnings.push(`releasePolicy.blockOn: use severities from ${SEVERITIES.join(', ')}; invalid entries ignored.`);
    }
    if (Array.isArray(r.blockOn)) policy.blockOn = [...new Set(valid)];
  }
  if (r.requireAreas !== undefined) {
    const list = Array.isArray(r.requireAreas) ? r.requireAreas : [];
    const valid = list.filter(
      (s): s is string => typeof s === 'string' && (AREA_NAMES.includes(s) || /^static-[a-z]+$/.test(s)),
    );
    if (!Array.isArray(r.requireAreas) || valid.length !== list.length) {
      warnings.push(`releasePolicy.requireAreas: use areas from ${AREA_NAMES.join(', ')} (or static-<language>); invalid entries ignored.`);
    }
    if (Array.isArray(r.requireAreas)) policy.requireAreas = [...new Set(valid)];
  }
  if (r.treatUnverifiedCriticalAs !== undefined) {
    if (r.treatUnverifiedCriticalAs === 'review-required' || r.treatUnverifiedCriticalAs === 'not-ready') {
      policy.treatUnverifiedCriticalAs = r.treatUnverifiedCriticalAs;
    } else {
      warnings.push(
        'releasePolicy.treatUnverifiedCriticalAs must be "review-required" or "not-ready" (an unverified critical is never hidden or "ready"); using "review-required".',
      );
    }
  }
  return { policy, warnings };
}

/** Validate a --fail-on-release-state value. "ready" is not a threshold (it would always fail). */
export function parseReleaseStateThreshold(value: string): ReleaseState {
  const v = value.toLowerCase();
  if (v !== 'ready' && (RELEASE_STATES as string[]).includes(v)) return v as ReleaseState;
  throw new Error(
    `Invalid --fail-on-release-state "${value}". Use one of: ${RELEASE_STATES.filter((s) => s !== 'ready').join(', ')}.`,
  );
}

/** True when `state` is at or worse than `threshold`. */
export function releaseAtOrWorse(state: ReleaseState, threshold: ReleaseState): boolean {
  return RANK[state] >= RANK[threshold];
}

/** The severity a finding's source suggested (unverified findings are stored demoted to info). */
export function suggestedSeverity(f: Finding): Severity {
  if (f.suggestedSeverity) return f.suggestedSeverity;
  const m = /^AI-suggested severity: (critical|warning|info)\b/.exec(f.description ?? '');
  return (m?.[1] as Severity | undefined) ?? f.severity;
}

export interface ReleaseContext {
  policy?: ReleasePolicy;
  policyWarnings?: string[];
  /** Findings accepted by a baseline (grandfathered): they do not block, but the state says so. */
  accepted?: Finding[];
  /** Fix-verification counts, when known (MCP session, `analyze --fix`). */
  verification?: { fixedVerified: number; fixedUnverified: number };
}

function isMandatory(a: CoverageArea, policy: ReleasePolicy): boolean {
  return Boolean(a.requested) || policy.requireAreas.some((r) => r === a.id || r === a.kind);
}

const plural = (n: number, word: string): string => `${n} ${word}`;

/** Compute the release assessment for a report. Pure. */
export function assessRelease(report: Pick<ScanReport, 'findings' | 'coverage'>, ctx: ReleaseContext = {}): ReleaseAssessment {
  const policy = ctx.policy ?? DEFAULT_RELEASE_POLICY;
  const block = new Set<Severity>(policy.blockOn);
  const acceptedSet = new Set(ctx.accepted ?? []);
  const acceptedIds = new Set((ctx.accepted ?? []).map((f) => f.id));
  const isAccepted = (f: Finding): boolean => acceptedSet.has(f) || acceptedIds.has(f.id);

  const counts = { critical: 0, warning: 0, info: 0 };
  let confirmed = 0;
  let suspected = 0;
  let unverified = 0;
  let ai = 0;
  let accepted = 0;
  let unverifiedBlocking = 0;
  let suspectedBlocking = 0;
  let open = 0;
  for (const f of report.findings) {
    if (isUnverified(f)) {
      unverified++;
      if (f.source === 'ai') ai++;
      if (block.has(suggestedSeverity(f))) unverifiedBlocking++;
      continue;
    }
    if (isNote(f) || isNonScored(f)) continue;
    if (isAccepted(f)) {
      accepted++;
      continue;
    }
    open++;
    if (f.guessed) {
      suspected++;
      if (block.has(f.severity)) suspectedBlocking++;
      continue;
    }
    confirmed++;
    counts[f.severity]++;
  }

  const coverage = (report.coverage ?? []).map((a) => ({ ...a, mandatory: isMandatory(a, policy) }));
  const confirmedBlocking = SEVERITIES.filter((s) => block.has(s)).reduce((n, s) => n + counts[s], 0);
  const mandatoryMissing = coverage.filter((a) => a.mandatory && (a.state === 'failed' || a.state === 'untested'));
  const otherFailed = coverage.filter((a) => !a.mandatory && a.state === 'failed');
  const mandatoryInconclusive = coverage.filter((a) => a.mandatory && a.state === 'inconclusive');
  const limitedCoverage = !coverage.some((a) => a.live && a.state === 'passed');

  const reasons: string[] = [];
  const blockingText = SEVERITIES.filter((s) => block.has(s) && counts[s] > 0)
    .map((s) => `${counts[s]} confirmed ${s}`)
    .join(', ');
  if (confirmedBlocking > 0) reasons.push(blockingText);
  const unconfirmedText: string[] = [];
  if (unverifiedBlocking) unconfirmedText.push(`${plural(unverifiedBlocking, ai ? 'unverified/AI' : 'unverified')} ${policy.blockOn.join('/')} to review`);
  if (suspectedBlocking) unconfirmedText.push(`${suspectedBlocking} suspected ${policy.blockOn.join('/')} (guessed path) to review`);
  const unconfirmedAsNotReady = policy.treatUnverifiedCriticalAs === 'not-ready' && unverifiedBlocking + suspectedBlocking > 0;
  if (unconfirmedAsNotReady) reasons.push(...unconfirmedText);
  for (const a of mandatoryMissing) {
    reasons.push(a.state === 'failed' ? `${a.label} check failed (scanner error is not a pass)` : `${a.label} required but untested`);
  }
  if (!unconfirmedAsNotReady) reasons.push(...unconfirmedText);
  for (const a of otherFailed) reasons.push(`${a.label} check failed (scanner error is not a pass)`);
  for (const a of mandatoryInconclusive) reasons.push(`${a.label} inconclusive`);

  let state: ReleaseState;
  if (confirmedBlocking > 0 || unconfirmedAsNotReady) state = 'not-ready';
  else if (mandatoryMissing.length > 0) state = 'insufficient-evidence';
  else if (unverifiedBlocking + suspectedBlocking > 0 || otherFailed.length > 0 || mandatoryInconclusive.length > 0) state = 'review-required';
  else if (accepted > 0) state = 'ready-with-accepted-risks';
  else state = 'ready';

  if (state === 'ready-with-accepted-risks') reasons.push(`${accepted} accepted risk(s) in the baseline`);
  if (state === 'ready' || state === 'ready-with-accepted-risks') {
    reasons.push(
      confirmed === 0
        ? 'no confirmed findings'
        : `no confirmed ${policy.blockOn.join('/') || 'blocking'} findings (${confirmed} lower-severity open)`,
    );
  }

  const verification = {
    fixedVerified: ctx.verification?.fixedVerified ?? 0,
    fixedUnverified: ctx.verification?.fixedUnverified ?? 0,
    open,
  };
  const assessment: ReleaseAssessment = {
    state,
    limitedCoverage,
    reasons,
    findings: counts,
    confidence: { confirmed, unverified, ai, suspected, unconfirmedBlocking: unverifiedBlocking + suspectedBlocking },
    verification,
    accepted,
    policy,
    line: '',
    ...(ctx.policyWarnings?.length ? { policyWarnings: ctx.policyWarnings } : {}),
  };
  assessment.line = releaseLine(assessment, coverage);
  return assessment;
}

const STATE_LABEL: Record<ReleaseState, string> = {
  ready: 'READY',
  'ready-with-accepted-risks': 'READY WITH ACCEPTED RISKS',
  'review-required': 'REVIEW REQUIRED',
  'not-ready': 'NOT READY',
  'insufficient-evidence': 'INSUFFICIENT EVIDENCE',
};

/** "READY (limited coverage)" etc. */
export function releaseLabel(r: Pick<ReleaseAssessment, 'state' | 'limitedCoverage'>): string {
  const base = STATE_LABEL[r.state];
  return (r.state === 'ready' || r.state === 'ready-with-accepted-risks') && r.limitedCoverage
    ? `${base} under limited coverage`
    : base;
}

/** The headline: "Release: NOT READY — 2 confirmed critical · Coverage: static ✓ · ...". */
export function releaseLine(r: Pick<ReleaseAssessment, 'state' | 'limitedCoverage' | 'reasons'>, coverage: CoverageArea[]): string {
  const why = r.reasons.slice(0, 2).join('; ');
  const cov = coverage.length ? ` · Coverage: ${coverageSummary(coverage)}` : '';
  return `Release: ${releaseLabel(r)}${why ? ` — ${why}` : ''}${cov}`;
}

/** Attach `coverage[].mandatory` and `release` to a report (returns a new object). */
export function withRelease<T extends Pick<ScanReport, 'findings' | 'coverage'>>(report: T, ctx: ReleaseContext = {}): T & { release: ReleaseAssessment } {
  const policy = ctx.policy ?? DEFAULT_RELEASE_POLICY;
  const coverage = report.coverage?.map((a) => ({ ...a, mandatory: isMandatory(a, policy) }));
  return { ...report, ...(coverage ? { coverage } : {}), release: assessRelease(report, { ...ctx, policy }) };
}
