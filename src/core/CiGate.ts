/**
 * CI gating: decide whether a scan should fail the build, and produce a clean
 * machine-readable JSON summary. Used by `deployready analyze --fail-on <sev>`.
 *
 * Exit codes (so CI can tell a policy failure from a tool crash):
 *   0  clean — no findings at/above the threshold
 *   1  runtime error (the CLI threw)
 *   2  gate exceeded — findings at/above the threshold
 */
import { ScoreCalculator } from '../analysis/ScoreCalculator';
import type { Finding, ScanReport } from '../types';

export type FailOn = 'critical' | 'warning' | 'info' | 'none';

export const FAIL_ON_VALUES: FailOn[] = ['critical', 'warning', 'info', 'none'];

export const EXIT = { OK: 0, ERROR: 1, GATE: 2 } as const;

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
// A baseline lets CI accept the current set of findings and fail only on NEW
// ones. Fingerprints deliberately ignore the line number so a known issue that
// merely shifts lines stays "known" instead of re-failing the build.

const BASELINE_FORMAT = 'deployready-baseline/1';

/** Stable, line-insensitive identity for a finding. */
export function fingerprint(f: Pick<Finding, 'rule' | 'file' | 'endpoint'>): string {
  return `${f.rule}:${f.file ?? ''}:${f.endpoint ?? ''}`;
}

/** Serialize the current findings into a baseline file body (JSON). */
export function serializeBaseline(findings: Finding[]): string {
  const fingerprints = Array.from(new Set(findings.map(fingerprint))).sort();
  return JSON.stringify({ format: BASELINE_FORMAT, fingerprints }, null, 2) + '\n';
}

/** Parse a baseline file body into a fingerprint set. Tolerant of junk/empty. */
export function readBaseline(text: string): Set<string> {
  try {
    const parsed = JSON.parse(text) as { fingerprints?: unknown };
    if (Array.isArray(parsed.fingerprints)) {
      return new Set(parsed.fingerprints.filter((x): x is string => typeof x === 'string'));
    }
  } catch {
    /* fall through */
  }
  return new Set();
}

/** Findings whose fingerprint is not present in the baseline. */
export function newFindings(findings: Finding[], baseline: Set<string>): Finding[] {
  return findings.filter((f) => !baseline.has(fingerprint(f)));
}

/** Recompute a severity breakdown for an arbitrary finding subset. */
export function summarize(findings: Finding[]): ScanReport['summary'] {
  return ScoreCalculator.summarize(findings);
}

/** Compact, CI-friendly JSON view of a report. Evidence is already redacted. */
export function toCiJson(report: ScanReport, failOn: FailOn): Record<string, unknown> {
  return {
    tool: 'deployready',
    version: report.version,
    target: report.target,
    stack: report.stack.stack,
    score: report.score,
    summary: report.summary,
    failOn,
    passed: !shouldFail(report.summary, failOn),
    findings: report.findings.map((f) => ({
      rule: f.rule,
      title: f.title,
      severity: f.severity,
      category: f.category,
      source: f.source,
      file: f.file,
      line: f.line,
      endpoint: f.endpoint,
      owasp: f.owasp,
      cwe: f.cwe,
    })),
  };
}
