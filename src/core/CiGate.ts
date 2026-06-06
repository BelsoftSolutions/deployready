/**
 * CI gating: decide whether a scan should fail the build, and produce a clean
 * machine-readable JSON summary. Used by `deployready analyze --fail-on <sev>`.
 *
 * Exit codes (so CI can tell a policy failure from a tool crash):
 *   0  clean — no findings at/above the threshold
 *   1  runtime error (the CLI threw)
 *   2  gate exceeded — findings at/above the threshold
 */
import type { ScanReport } from '../types';

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
