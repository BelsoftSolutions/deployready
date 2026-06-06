/**
 * Recomputes the production-readiness score from the currently-open findings,
 * so the number moves as the user marks issues fixed.
 */
import { ScoreCalculator } from '../analysis/ScoreCalculator';
import type { Finding } from '../types';

export class ScoreTracker {
  static current(openFindings: Finding[]): number {
    return ScoreCalculator.calculate(ScoreCalculator.summarize(openFindings));
  }
}
