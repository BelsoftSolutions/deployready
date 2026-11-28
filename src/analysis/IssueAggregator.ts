/**
 * Combine findings from all sources (static + dynamic + AI), deduplicate,
 * apply severity policy, sort, and compute the final score + summary.
 *
 * Interface contract:
 *   const results = IssueAggregator.process(staticFindings, dynamicFindings, aiFindings);
 */
import type { Finding } from '../types';
import { SeverityScorer } from './SeverityScorer';
import { ScoreCalculator } from './ScoreCalculator';
import type { ScoreSummary } from './ScoreCalculator';

export interface AggregateResult {
  findings: Finding[];
  score: number;
  summary: ScoreSummary;
}

export class IssueAggregator {
  static process(...groups: Finding[][]): AggregateResult {
    const all = SeverityScorer.apply(groups.flat());
    const deduped = IssueAggregator.dedupe(all);
    deduped.sort((a, b) => {
      const sev = SeverityScorer.rank(a.severity) - SeverityScorer.rank(b.severity);
      if (sev !== 0) return sev;
      return a.category.localeCompare(b.category) || a.rule.localeCompare(b.rule);
    });

    const summary = ScoreCalculator.summarize(deduped);
    return { findings: deduped, score: ScoreCalculator.calculate(summary), summary };
  }

  /**
   * Dedup by id, then by semantic key (rule + location). Precedence keeps the
   * richer source: dynamic (confirmed live) > static > ai (inferred).
   */
  private static dedupe(findings: Finding[]): Finding[] {
    const rank = { dynamic: 0, static: 1, engine: 1.5, ai: 2 } as const;
    const rankOf = (f: Finding): number => rank[f.source.startsWith('engine:') ? 'engine' : (f.source as 'dynamic' | 'static' | 'ai')];
    const best = new Map<string, Finding>();

    for (const f of findings) {
      const key = `${f.rule}|${f.file ?? ''}|${f.line ?? ''}|${f.endpoint ?? ''}`;
      const existing = best.get(key);
      if (!existing || rankOf(f) < rankOf(existing)) {
        best.set(key, f);
      }
    }
    return [...best.values()];
  }
}
