/**
 * The single definition of "ready to ship" for the agent integration (MCP + `analyze --fix`).
 * Ready means: no open critical findings. Warnings and info never block readiness; unverified AI
 * suggestions and informational notes are not counted (ScoreCalculator.summarize excludes them).
 */
import { ScoreCalculator } from '../analysis/ScoreCalculator';
import type { Finding } from '../types';

export interface Readiness {
  score: number;
  summary: ReturnType<typeof ScoreCalculator.summarize>;
  ready: boolean;
  verdict: string;
}

export function assess(findings: Finding[]): Readiness {
  const summary = ScoreCalculator.summarize(findings);
  const score = ScoreCalculator.calculate(summary);
  const ready = summary.critical === 0;
  const verdict = ready
    ? summary.warning + summary.info === 0
      ? 'READY: no open findings.'
      : `READY: no open critical findings (${summary.warning} warning, ${summary.info} info remain).`
    : `NOT READY: ${summary.critical} open critical finding${summary.critical === 1 ? '' : 's'}.`;
  return { score, summary, ready, verdict };
}
