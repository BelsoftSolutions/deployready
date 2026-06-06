/**
 * Normalizes/escalates finding severity. Detectors set a default severity;
 * this is the single place to apply cross-cutting policy (e.g. a hardcoded
 * secret is always critical regardless of where it came from).
 */
import type { Finding, Severity } from '../types';

const ALWAYS_CRITICAL = new Set(['hardcoded-secret', 'env-not-ignored', 'sql-injection', 'command-injection']);

export class SeverityScorer {
  static apply(findings: Finding[]): Finding[] {
    return findings.map((f) => {
      const severity: Severity = ALWAYS_CRITICAL.has(f.rule) ? 'critical' : f.severity;
      return severity === f.severity ? f : { ...f, severity };
    });
  }

  static rank(s: Severity): number {
    return s === 'critical' ? 0 : s === 'warning' ? 1 : 2;
  }
}
