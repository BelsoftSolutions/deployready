/**
 * Production-readiness score (0-100) from finding counts.
 *
 * The original spec formula (base 100, -20/critical, -5/warning, -1/info, floored
 * at 0) had a usability bug: any real app with ~5+ criticals hit 0 and STAYED at
 * 0 no matter how many issues you fixed, so the number never reflected progress.
 *
 * Instead we sum weighted penalty points and apply a smooth rational decay:
 *   score = 100 · K / (K + penalty)
 * which is always > 0 while any issue remains, equals 100 only when fully clean,
 * and strictly rises every time an issue is resolved — so progress is visible.
 */
import type { Finding } from '../types';

const WEIGHT = { critical: 10, warning: 3, info: 1 } as const;
/** Decay constant: penalty == K gives a 50/100 score. */
const K = 30;

export interface ScoreSummary {
  critical: number;
  warning: number;
  info: number;
  /** Scored findings only; unverified AI suggestions and notes are excluded. */
  total: number;
  /** Unverified AI suggestions: displayed, never scored or gated on. */
  unverified?: number;
  /** Informational notes: displayed, never scored or gated on. */
  notes?: number;
}

/** Model output is never trusted: any AI-sourced finding is unverified. */
export function isUnverified(f: Pick<Finding, 'source' | 'unverified'>): boolean {
  return f.unverified === true || f.source === 'ai';
}

export function isNote(f: Pick<Finding, 'note'>): boolean {
  return f.note === true;
}

/** Findings that are displayed but never scored, gated on, or baselined. */
export function isNonScored(f: Pick<Finding, 'source' | 'unverified' | 'note'>): boolean {
  return isUnverified(f) || isNote(f);
}

export class ScoreCalculator {
  static summarize(findings: Finding[]): ScoreSummary & { unverified: number; notes: number } {
    let critical = 0;
    let warning = 0;
    let info = 0;
    let unverified = 0;
    let notes = 0;
    for (const f of findings) {
      if (isUnverified(f)) unverified++;
      else if (isNote(f)) notes++;
      else if (f.severity === 'critical') critical++;
      else if (f.severity === 'warning') warning++;
      else info++;
    }
    return { critical, warning, info, total: critical + warning + info, unverified, notes };
  }

  static calculate(summary: ScoreSummary): number {
    const penalty =
      summary.critical * WEIGHT.critical + summary.warning * WEIGHT.warning + summary.info * WEIGHT.info;
    if (penalty <= 0) return 100;
    // Always leave at least 1 so a non-clean app never reads a flat 0.
    return Math.max(1, Math.round((100 * K) / (K + penalty)));
  }
}
