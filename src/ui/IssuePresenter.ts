/**
 * Pretty-prints the scan report to the terminal with severity badges, grouped
 * counts, and the production-readiness score. Output is already redacted because
 * findings only ever carry redacted evidence.
 */
import chalk from 'chalk';
import { isNote, isNonScored, isUnverified } from '../analysis/ScoreCalculator';
import type { Finding, ScanReport, Severity } from '../types';
import { COMMON_PATH_TITLE, OUTCOME_LABEL, capLine, commonPathReport, controlLine, guessedFindings, isGuessed } from './commonPathSection';

const BADGE: Record<Severity, string> = {
  critical: chalk.red.bold('CRITICAL'),
  warning: chalk.yellow.bold('WARNING'),
  info: chalk.blue.bold('INFO'),
};

const HEADER: Record<Severity, (s: string) => string> = {
  critical: (s) => chalk.red.bold(s),
  warning: (s) => chalk.yellow.bold(s),
  info: (s) => chalk.blue.bold(s),
};

export class IssuePresenter {
  static display(report: ScanReport): void {
    const bar = '━'.repeat(48);
    console.log('\n' + bar);
    console.log('  ' + chalk.bold('DeployReady Scan Results'));
    console.log('  ' + chalk.bold(`Production Readiness Score: ${scoreColor(report.score)}/100`));
    console.log(`  Stack: ${report.stack.stack} (${report.stack.language})  ·  Files: ${report.graph.fileCount}  ·  Routes: ${report.graph.routes.length}`);
    console.log(bar + '\n');

    if (report.aiSummary) {
      console.log(chalk.cyan('🤖 AI Summary (unverified)'));
      console.log('  ' + report.aiSummary.replace(/\n/g, '\n  ') + '\n');
    }

    for (const sev of ['critical', 'warning', 'info'] as Severity[]) {
      const group = report.findings.filter((f) => f.severity === sev && !isNonScored(f) && !isGuessed(f));
      if (!group.length) continue;
      console.log(HEADER[sev](`${icon(sev)} ${sev.toUpperCase()} (${group.length})`));
      group.forEach((f, i) => IssuePresenter.printFinding(f, i + 1));
      console.log('');
    }

    const suggestions = report.findings.filter(isUnverified);
    const notes = report.findings.filter(isNote);
    if (suggestions.length) {
      console.log(chalk.magenta.bold(`🤖 AI SUGGESTIONS (unverified, not scored) (${suggestions.length})`));
      suggestions.forEach((f, i) => IssuePresenter.printFinding(f, i + 1));
      console.log('');
    }

    if (notes.length) {
      console.log(chalk.gray.bold(`ℹ️  NOTES (not scored) (${notes.length})`));
      notes.forEach((f, i) => IssuePresenter.printFinding(f, i + 1));
      console.log('');
    }

    IssuePresenter.printCommonPaths(report);

    if (report.summary.total === 0 && suggestions.length === 0 && notes.length === 0) {
      console.log(chalk.green('✓ No issues detected. Nice work — but keep validating in CI.\n'));
    } else {
      console.log(
        chalk.bold(
          `Summary: ${report.summary.critical} critical, ${report.summary.warning} warnings, ${report.summary.info} info`,
        ) + '\n',
      );
      if (suggestions.length) {
        console.log(chalk.magenta(`${suggestions.length} AI suggestions (unverified, not scored)\n`));
      }
      if (notes.length) console.log(chalk.gray(`${notes.length} notes (not scored)\n`));
    }
  }

  private static printCommonPaths(report: ScanReport): void {
    const cp = commonPathReport(report);
    if (!cp) return;
    const guessed = guessedFindings(report.findings);
    console.log(chalk.cyan.bold(`🔎 ${COMMON_PATH_TITLE}`));
    console.log(chalk.gray(`  Target ${cp.target}; ${controlLine(cp)}; ${capLine(cp)}.`));
    console.log(chalk.gray('  Guessed findings count in the summary and score at their capped severity.'));
    if (guessed.length) {
      console.log(`  Guessed findings (${guessed.length}):`);
      guessed.forEach((f, i) => IssuePresenter.printFinding(f, i + 1));
    } else {
      console.log('  No guessed path was proven exposed.');
    }
    console.log(`  Requested paths (${cp.probed.length}):`);
    for (const p of cp.probed) {
      const label = OUTCOME_LABEL[p.outcome].padEnd(10);
      console.log(chalk.gray(`    ${label} GET ${p.path} -> ${p.status ?? 'no response'}  ${p.reason}`));
    }
    if (cp.covered?.length) console.log(chalk.gray(`  Covered by the normal scan, not requested again: ${cp.covered.join(', ')}`));
    if (cp.aborted) console.log(chalk.yellow(`  Aborted: ${cp.aborted}`));
    console.log('');
  }

  private static printFinding(f: Finding, n: number): void {
    const loc = f.endpoint ?? (f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '');
    const refs = [f.owasp, f.cwe].filter(Boolean).join(' ');
    console.log(`  ${n}. ${f.title}${loc ? chalk.gray(`  — ${loc}`) : ''}`);
    const badge = isUnverified(f) ? chalk.magenta.bold('UNVERIFIED') : isNote(f) ? chalk.gray.bold('NOTE') : BADGE[f.severity];
    if (refs || isUnverified(f) || isNote(f)) console.log(chalk.gray(`     ${refs ? `${refs}  ·  ` : ''}${badge} ${chalk.gray(`[${f.source}]`)}`));
    if (isNonScored(f) && f.description) console.log(chalk.gray(`     ${f.description}`));
    if (f.evidence) console.log(chalk.gray(`     evidence: ${f.evidence}`));
    console.log(chalk.gray(`     fix: ${f.recommendation}`));
  }
}

function icon(sev: Severity): string {
  return sev === 'critical' ? '🔴' : sev === 'warning' ? '🟡' : '🔵';
}

function scoreColor(score: number): string {
  const s = String(score);
  if (score >= 80) return chalk.green.bold(s);
  if (score >= 50) return chalk.yellow.bold(s);
  return chalk.red.bold(s);
}
