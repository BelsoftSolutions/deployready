/**
 * Pretty-prints the scan report to the terminal with severity badges, grouped
 * counts, and the production-readiness score. Output is already redacted because
 * findings only ever carry redacted evidence.
 */
import chalk from 'chalk';
import type { Finding, ScanReport, Severity } from '../types';

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
      console.log(chalk.cyan('🤖 AI Summary'));
      console.log('  ' + report.aiSummary.replace(/\n/g, '\n  ') + '\n');
    }

    for (const sev of ['critical', 'warning', 'info'] as Severity[]) {
      const group = report.findings.filter((f) => f.severity === sev);
      if (!group.length) continue;
      console.log(HEADER[sev](`${icon(sev)} ${sev.toUpperCase()} (${group.length})`));
      group.forEach((f, i) => IssuePresenter.printFinding(f, i + 1));
      console.log('');
    }

    if (report.summary.total === 0) {
      console.log(chalk.green('✓ No issues detected. Nice work — but keep validating in CI.\n'));
    } else {
      console.log(
        chalk.bold(
          `Summary: ${report.summary.critical} critical, ${report.summary.warning} warnings, ${report.summary.info} info`,
        ) + '\n',
      );
    }
  }

  private static printFinding(f: Finding, n: number): void {
    const loc = f.endpoint ?? (f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '');
    const refs = [f.owasp, f.cwe].filter(Boolean).join(' ');
    console.log(`  ${n}. ${f.title}${loc ? chalk.gray(`  — ${loc}`) : ''}`);
    if (refs) console.log(chalk.gray(`     ${refs}  ·  ${BADGE[f.severity]} ${chalk.gray(`[${f.source}]`)}`));
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
