/**
 * CI gating: decide whether a scan should fail the build, and produce a clean
 * machine-readable JSON summary. Used by `deployready analyze --fail-on <sev>`.
 *
 * Exit codes (so CI can tell a policy failure from a tool crash):
 *   0  clean — no findings at/above the threshold (and, with --fail-on-release-state, the release
 *      state is better than the threshold)
 *   1  runtime error (the CLI threw)
 *   2  gate exceeded — findings at/above the threshold, or the release state is at/worse than
 *      the --fail-on-release-state threshold
 *   3  insufficient evidence — only with --fail-on-release-state: a mandatory check area errored
 *      or did not run, so the scan cannot say the release is safe (scanner failure is never a pass)
 */
import { ScoreCalculator, isNonScored, isUnverified } from '../analysis/ScoreCalculator';
import type { Finding, ReleaseAssessment, ReleaseState, ScanReport } from '../types';
import { SCORE_DISCLAIMER, releaseAtOrWorse } from './releaseState';
import { buildFixPrompt } from '../agent/fixPrompt';
import { fingerprintAll, normalizePath } from './baselineFingerprint';
import { COMMON_PATH_TITLE, guessedFindings, normalFindings } from '../ui/commonPathSection';

export type FailOn = 'critical' | 'warning' | 'info' | 'none';

export const FAIL_ON_VALUES: FailOn[] = ['critical', 'warning', 'info', 'none'];

export const EXIT = { OK: 0, ERROR: 1, GATE: 2, INSUFFICIENT_EVIDENCE: 3 } as const;

/**
 * Exit code for --fail-on-release-state. `undefined` threshold = flag not given = never gates.
 * 3 only when the state is insufficient-evidence; 2 for any other state at/worse than the threshold.
 */
export function releaseExitCode(release: ReleaseAssessment | undefined, threshold: ReleaseState | undefined): number {
  if (!threshold || !release) return EXIT.OK;
  if (!releaseAtOrWorse(release.state, threshold)) return EXIT.OK;
  return release.state === 'insufficient-evidence' ? EXIT.INSUFFICIENT_EVIDENCE : EXIT.GATE;
}

/** Validate a --fail-on value, throwing a helpful error otherwise. */
export function parseFailOn(value: string): FailOn {
  const v = value.toLowerCase();
  if ((FAIL_ON_VALUES as string[]).includes(v)) return v as FailOn;
  throw new Error(`Invalid --fail-on "${value}". Use one of: ${FAIL_ON_VALUES.join(', ')}.`);
}

/** True if the report should fail the build under the given threshold. */
export function shouldFail(summary: ScanReport['summary'], failOn: FailOn): boolean {
  switch (failOn) {
    case 'critical':
      return summary.critical > 0;
    case 'warning':
      return summary.critical + summary.warning > 0;
    case 'info':
      return summary.total > 0;
    case 'none':
    default:
      return false;
  }
}

// ---- Baseline support -------------------------------------------------------
// A baseline lets CI accept the current set of findings and fail only on what is NOT
// accepted. v2 identity is a move-stable, collision-resistant fingerprint (see
// baselineFingerprint.ts); severity is tracked separately so escalation is caught.
// v1 baselines ("rule:file:endpoint" strings) are still read, with a migration warning.

export const BASELINE_VERSION = 2;
const BASELINE_FORMAT = 'deployready-baseline/2';

const SEV_RANK: Record<string, number> = { info: 0, warning: 1, critical: 2 };

export interface BaselineEntry {
  fingerprint: string;
  rule: string;
  file: string;
  severity: string;
  acceptedAt: string;
  reason: string | null;
  owner: string | null;
  expiresAt?: string;
  /** Set when a --write-baseline run found the issue gone. A match later means "reopened". */
  resolvedAt?: string;
  /** Entry came from a v1 file: identity is the old line-insensitive key, severity unknown. */
  legacy?: boolean;
}

export interface Baseline {
  version: number;
  entries: BaselineEntry[];
  warnings: string[];
}

/** v1 identity: line-insensitive but collision-prone. Kept only to read old baselines. */
export function fingerprint(f: Pick<Finding, 'rule' | 'file' | 'endpoint'>): string {
  return `${f.rule}:${f.file ?? ''}:${f.endpoint ?? ''}`;
}

const today = (now: Date): string => now.toISOString().slice(0, 10);

/** Parse a baseline body (v2 or v1). Tolerant of junk/empty: yields no entries. */
export function parseBaseline(text: string): Baseline {
  const empty: Baseline = { version: BASELINE_VERSION, entries: [], warnings: [] };
  let parsed: { version?: unknown; entries?: unknown; fingerprints?: unknown };
  try {
    parsed = JSON.parse(text);
  } catch {
    return empty;
  }
  if (!parsed || typeof parsed !== 'object') return empty;
  if (Array.isArray(parsed.entries)) {
    const entries = (parsed.entries as Record<string, unknown>[])
      .filter((e) => e && typeof e.fingerprint === 'string')
      .map((e): BaselineEntry => ({
        fingerprint: e.fingerprint as string,
        rule: String(e.rule ?? ''),
        file: String(e.file ?? ''),
        severity: String(e.severity ?? 'info'),
        acceptedAt: String(e.acceptedAt ?? ''),
        reason: typeof e.reason === 'string' ? e.reason : null,
        owner: typeof e.owner === 'string' ? e.owner : null,
        ...(typeof e.expiresAt === 'string' ? { expiresAt: e.expiresAt } : {}),
        ...(typeof e.resolvedAt === 'string' ? { resolvedAt: e.resolvedAt } : {}),
      }));
    return { version: BASELINE_VERSION, entries, warnings: [] };
  }
  if (Array.isArray(parsed.fingerprints)) {
    const entries = parsed.fingerprints
      .filter((x): x is string => typeof x === 'string')
      .map((fp): BaselineEntry => {
        const [rule = '', file = ''] = fp.split(':');
        return { fingerprint: fp, rule, file, severity: '', acceptedAt: '', reason: null, owner: null, legacy: true };
      });
    return {
      version: 1,
      entries,
      warnings: [
        'Baseline is the old v1 format: it matches by rule+file only (a second issue of the same rule in the same file is NOT detected) and records no severity, reason or owner. Re-run with --write-baseline to migrate to v2.',
      ],
    };
  }
  return empty;
}

/**
 * Serialize the current findings into a v2 baseline body. Passing the previous baseline keeps
 * reason/owner/acceptedAt/expiresAt of entries that still match, and records entries whose
 * finding disappeared as resolved (so a later reappearance is "reopened", not silently re-accepted).
 * Output is sorted and key-ordered so diffs show exactly what changed.
 */
export function serializeBaseline(
  findings: Finding[],
  opts: { root?: string; previous?: Baseline; now?: Date } = {},
): string {
  const now = opts.now ?? new Date();
  const prev = new Map((opts.previous?.entries ?? []).map((e) => [e.fingerprint, e]));
  const scored = findings.filter((f) => !isNonScored(f));
  const fps = fingerprintAll(scored, opts.root ?? '.');
  const live = new Set(fps.map((x) => x.fingerprint));
  const entries: BaselineEntry[] = fps.map(({ finding: f, fingerprint: fp }) => {
    const old = prev.get(fp) ?? prev.get(fingerprint(f));
    return {
      fingerprint: fp,
      rule: f.rule,
      file: normalizePath(f.file),
      severity: f.severity,
      acceptedAt: old && !old.resolvedAt && old.acceptedAt ? old.acceptedAt : today(now),
      reason: old?.reason ?? null,
      owner: old?.owner ?? null,
      ...(old?.expiresAt ? { expiresAt: old.expiresAt } : {}),
    };
  });
  for (const old of prev.values()) {
    if (old.legacy || live.has(old.fingerprint)) continue;
    entries.push({ ...old, resolvedAt: old.resolvedAt ?? today(now) });
  }
  entries.sort((a, b) => a.file.localeCompare(b.file) || a.rule.localeCompare(b.rule) || a.fingerprint.localeCompare(b.fingerprint));
  const ordered = entries.map((e) => ({
    fingerprint: e.fingerprint,
    rule: e.rule,
    file: e.file,
    severity: e.severity,
    acceptedAt: e.acceptedAt,
    reason: e.reason,
    owner: e.owner,
    ...(e.expiresAt ? { expiresAt: e.expiresAt } : {}),
    ...(e.resolvedAt ? { resolvedAt: e.resolvedAt } : {}),
  }));
  return JSON.stringify({ version: BASELINE_VERSION, format: BASELINE_FORMAT, entries: ordered }, null, 2) + '\n';
}

/** Legacy helper: the set of fingerprints in a baseline body. */
export function readBaseline(text: string): Set<string> {
  return new Set(parseBaseline(text).entries.map((e) => e.fingerprint));
}

export interface BaselineStale {
  fingerprint: string;
  rule: string;
  file: string;
}

export interface BaselineComparison {
  /** Not in the baseline at all. */
  new: Finding[];
  /** Accepted at a lower severity; now worse. */
  escalated: { finding: Finding; was: string }[];
  /** Accepted once, resolved, now back. */
  reopened: Finding[];
  /** Accepted, but the suppression's expiresAt has passed. */
  expired: Finding[];
  /** Suppressions with no matching finding (candidates to remove). */
  stale: BaselineStale[];
  /** Findings that are still suppressed. */
  known: Finding[];
  /** Non-scored findings, always listed, never gated. */
  nonScored: Finding[];
  warnings: string[];
}

/** Compare findings against a baseline. Pure given `root` contents and `now`. */
export function compareToBaseline(
  findings: Finding[],
  baseline: Baseline,
  opts: { root?: string; now?: Date } = {},
): BaselineComparison {
  const nowDay = today(opts.now ?? new Date());
  const res: BaselineComparison = { new: [], escalated: [], reopened: [], expired: [], stale: [], known: [], nonScored: [], warnings: [...baseline.warnings] };
  const byFp = new Map(baseline.entries.map((e) => [e.fingerprint, e]));
  const matched = new Set<string>();
  const scored = findings.filter((f) => !isNonScored(f));
  res.nonScored = findings.filter(isNonScored);
  for (const { finding: f, fingerprint: fp } of fingerprintAll(scored, opts.root ?? '.')) {
    const e = byFp.get(fp) ?? byFp.get(fingerprint(f));
    if (!e) {
      res.new.push(f);
      continue;
    }
    matched.add(e.fingerprint);
    if (e.resolvedAt) res.reopened.push(f);
    else if (e.expiresAt && e.expiresAt < nowDay) res.expired.push(f);
    else if (!e.legacy && (SEV_RANK[f.severity] ?? 0) > (SEV_RANK[e.severity] ?? 0)) res.escalated.push({ finding: f, was: e.severity });
    else res.known.push(f);
  }
  for (const e of baseline.entries) {
    if (!matched.has(e.fingerprint) && !e.resolvedAt) res.stale.push({ fingerprint: e.fingerprint, rule: e.rule, file: e.file });
  }
  return res;
}

/** Findings that must be counted by the gate (everything not still suppressed). */
export function gatedFindings(c: BaselineComparison): Finding[] {
  return [...c.new, ...c.escalated.map((x) => x.finding), ...c.reopened, ...c.expired, ...c.nonScored];
}

/** One-line-per-category human summary for the gate output. */
export function describeComparison(c: BaselineComparison): string[] {
  const line = (label: string, n: number, extra = ''): string => `  ${label}: ${n}${extra}`;
  return [
    line('new', c.new.length),
    line('escalated', c.escalated.length, c.escalated.length ? ` (${c.escalated.map((x) => `${x.finding.rule} ${x.was}->${x.finding.severity}`).join(', ')})` : ''),
    line('reopened', c.reopened.length),
    line('expired', c.expired.length),
    line('stale', c.stale.length, c.stale.length ? ' (no matching finding; remove with --write-baseline)' : ''),
  ];
}

/** Findings whose v1 fingerprint is not in the set (legacy API, kept for compatibility). */
export function newFindings(findings: Finding[], baseline: Set<string>): Finding[] {
  return findings.filter((f) => isNonScored(f) || !baseline.has(fingerprint(f)));
}

/** Recompute a severity breakdown for an arbitrary finding subset. */
export function summarize(findings: Finding[]): ScanReport['summary'] {
  return ScoreCalculator.summarize(findings);
}

/** Compact, CI-friendly JSON view of a report. Evidence is already redacted. */
export function toCiJson(
  report: ScanReport,
  failOn: FailOn,
  cmp?: BaselineComparison,
  opts: { failOnReleaseState?: ReleaseState } = {},
): Record<string, unknown> {
  const cp = report.dynamic?.commonPaths;
  const out: Record<string, unknown> = {
    tool: 'deployready',
    version: report.version,
    target: report.target,
    stack: report.stack.stack,
    score: report.score,
    scoreNote: SCORE_DISCLAIMER,
    summary: report.summary,
    failOn,
    passed: !shouldFail(cmp ? summarize(gatedFindings(cmp)) : report.summary, failOn),
    ...(report.release ? { release: report.release } : {}),
    ...(report.coverage ? { coverage: report.coverage } : {}),
    ...(report.authz ? { authz: report.authz } : {}),
    ...(opts.failOnReleaseState
      ? {
          failOnReleaseState: opts.failOnReleaseState,
          releaseGatePassed: releaseExitCode(report.release, opts.failOnReleaseState) === EXIT.OK,
        }
      : {}),
    findings: normalFindings(report.findings).map(ciFinding),
  };
  if (cmp) {
    const ids = (fs: Finding[]) => fs.map((f) => ({ rule: f.rule, severity: f.severity, file: f.file, line: f.line }));
    out.baseline = {
      new: ids(cmp.new),
      escalated: cmp.escalated.map((x) => ({ ...ids([x.finding])[0], was: x.was })),
      reopened: ids(cmp.reopened),
      expired: ids(cmp.expired),
      stale: cmp.stale,
      known: cmp.known.length,
      warnings: cmp.warnings,
    };
  }
  // Only when the opt-in probe ran: guessed findings live here, not in `findings`; they are counted in `summary`.
  if (cp) {
    out.commonPathProbe = {
      title: COMMON_PATH_TITLE,
      countedInSummary: true,
      ...cp,
      findings: guessedFindings(report.findings).map((f) => ({ ...ciFinding(f), guessed: true, evidence: f.evidence })),
    };
  }
  return out;
}

function ciFinding(f: Finding): Record<string, unknown> {
  return {
    rule: f.rule,
    title: f.title,
    severity: f.severity,
    category: f.category,
    source: f.source,
    unverified: isUnverified(f),
    ...(isUnverified(f) && f.suggestedSeverity ? { suggestedSeverity: f.suggestedSeverity } : {}),
    note: f.note === true,
    file: f.file,
    line: f.line,
    endpoint: f.endpoint,
    owasp: f.owasp,
    cwe: f.cwe,
    // Paste-ready instruction for a coding agent (metadata only, no source code).
    fixPrompt: buildFixPrompt(f),
    // Reproducible evidence for live findings (redacted when it was built).
    ...(f.proof ? { proof: f.proof } : {}),
  };
}
