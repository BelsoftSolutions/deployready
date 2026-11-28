/**
 * `deployready analyze --fix`: after the scan, apply deterministic fixes, then re-scan and report the new score.
 */
import inquirer from 'inquirer';
import { Orchestrator } from '../core/Orchestrator';
import type { AnalyzeOptions } from '../core/Orchestrator';
import { logger } from '../utils/logger';
import { applySafeFixes, fixableFindings } from './fixes';
import type { SafeFixResult } from './fixes';
import type { ScanReport } from '../types';
import { withRelease } from '../core/releaseState';

export interface AnalyzeFixOutcome {
  /** The report to gate and print: the re-scan if anything was applied, else the original. */
  report: ScanReport;
  fix: SafeFixResult & { scoreBefore: number; scoreAfter: number; declined?: boolean };
}

export async function runAnalyzeFix(
  target: string,
  report: ScanReport,
  analyzeOpts: AnalyzeOptions,
  cli: { yes?: boolean; json?: boolean },
): Promise<AnalyzeFixOutcome> {
  const noop = (extra: { declined?: boolean } = {}): AnalyzeFixOutcome => ({
    report,
    fix: { applied: [], skipped: [], scoreBefore: report.score, scoreAfter: report.score, ...extra },
  });

  const fixable = fixableFindings(report.findings);
  if (fixable.length === 0) {
    logger.info('--fix: no safe automatic fixes available.');
    return noop();
  }

  // --yes / --json apply without asking; otherwise ask once (and never block a non-TTY run).
  if (!cli.yes && !cli.json) {
    let approved = false;
    if (process.stdin.isTTY) {
      ({ ok: approved } = await inquirer.prompt<{ ok: boolean }>([
        {
          type: 'confirm',
          name: 'ok',
          message: `Apply ${fixable.length} safe automatic fix${fixable.length === 1 ? '' : 'es'}? (a backup is created for each change)`,
          default: true,
        },
      ]));
    } else {
      logger.warn('--fix: not a terminal and --yes not given, so no changes were made.');
    }
    if (!approved) return noop({ declined: true });
  }

  const result = await applySafeFixes(target, fixable);
  for (const a of result.applied) {
    logger.success(`Fixed: ${a.title} (${a.file ?? ''}${a.line ? ':' + a.line : ''}); backup: ${a.backup ?? 'none'}`);
  }
  for (const s of result.skipped) logger.warn(`Skipped: ${s.title}: ${s.message}`);

  if (result.applied.length === 0) {
    return { report, fix: { ...result, scoreBefore: report.score, scoreAfter: report.score } };
  }

  const rescanned = await Orchestrator.analyze(target, {
    ...analyzeOpts,
    yes: true, // consent was already given for this run
    json: true, // the first scan printed the findings; only the new score is reported below
    noAi: true,
    open: false,
  });
  logger.success(`Re-scanned after ${result.applied.length} fix(es): score ${report.score} -> ${rescanned.score}.`);
  // The re-scan re-runs the static check that produced each fixed finding: gone = fixed-verified.
  const still = new Set(rescanned.findings.map((f) => f.id));
  const fixedVerified = result.applied.filter((a) => !still.has(a.id)).length;
  const verified = rescanned.release
    ? withRelease(rescanned, { policy: rescanned.release.policy, policyWarnings: rescanned.release.policyWarnings, verification: { fixedVerified, fixedUnverified: 0 } })
    : rescanned;
  return { report: verified, fix: { ...result, scoreBefore: report.score, scoreAfter: rescanned.score } };
}
