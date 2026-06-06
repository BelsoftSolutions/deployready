/**
 * Production-readiness score (0-100) from finding counts.
 * Formula from spec: base 100, -20 per critical, -5 per warning, -1 per info.
 */
import type { Finding } from '../types';

export interface ScoreSummary {
  critical: number;
  warning: number;
  info: number;
  total: number;
}

export class ScoreCalculator {
  static summarize(findings: Finding[]): ScoreSummary {
    let critical = 0;
    let warning = 0;
    let info = 0;
    for (const f of findings) {
      if (f.severity === 'critical') critical++;
      else if (f.severity === 'warning') warning++;
      else info++;
    }
    return { critical, warning, info, total: findings.length };
  }

  static calculate(summary: ScoreSummary): number {
    const base = 100 - summary.critical * 20 - summary.warning * 5 - summary.info * 1;
    return Math.max(0, Math.min(100, base));
  }
}
