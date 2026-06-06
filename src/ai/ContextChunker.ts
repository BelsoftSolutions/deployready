/**
 * Ensures the prompt fits a model's context window. Because we only ever send
 * the structured report (not code), trimming is simple: drop the lowest-severity
 * findings until the payload is under budget. Approximation: ~4 chars/token.
 */
import type { ScanReport } from '../types';

const CHARS_PER_TOKEN = 4;

export class ContextChunker {
  /**
   * Return a report whose findings list is trimmed so the serialized payload
   * stays under `maxTokens`. Highest-severity findings are kept first.
   */
  static fit(report: ScanReport, maxTokens: number): ScanReport {
    const budgetChars = maxTokens * CHARS_PER_TOKEN;
    if (JSON.stringify(report.findings).length <= budgetChars) return report;

    const order = { critical: 0, warning: 1, info: 2 } as const;
    const sorted = [...report.findings].sort((a, b) => order[a.severity] - order[b.severity]);

    const kept: typeof sorted = [];
    let size = 0;
    for (const f of sorted) {
      const cost = JSON.stringify(f).length;
      if (size + cost > budgetChars) break;
      kept.push(f);
      size += cost;
    }
    return { ...report, findings: kept };
  }
}
