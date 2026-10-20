/**
 * Shared pieces for the "Common-path probe (opt-in)" report section, so the
 * terminal, markdown, HTML and JSON outputs describe it identically.
 */
import type { CommonPathOutcome, CommonPathReport, Finding, ScanReport } from '../types';

export const COMMON_PATH_TITLE = 'Common-path probe (opt-in): guessed paths, lower confidence';

export const OUTCOME_LABEL: Record<CommonPathOutcome, string> = {
  found: 'found',
  'not-found': 'not found',
  protected: 'protected',
  'not-proven': 'not proven',
  error: 'error',
};

/** Guessed findings are listed in their own section, never in the normal severity lists. */
export function isGuessed(f: Pick<Finding, 'guessed'>): boolean {
  return f.guessed === true;
}

export function normalFindings(findings: Finding[]): Finding[] {
  return findings.filter((f) => !isGuessed(f));
}

export function guessedFindings(findings: Finding[]): Finding[] {
  return findings.filter(isGuessed);
}

/** The probe section is shown only when the probe actually ran. */
export function commonPathReport(report: ScanReport): CommonPathReport | undefined {
  return report.dynamic?.commonPaths;
}

export function controlLine(cp: CommonPathReport): string {
  return `control GET ${cp.control.path} -> ${cp.control.status ?? 'no response'}`;
}

export function capLine(cp: CommonPathReport): string {
  return `request cap: ${cp.cap} (including the control); ${cp.probed.length} well-known path(s) requested`;
}

export function probedLine(p: CommonPathReport['probed'][number]): string {
  return `${OUTCOME_LABEL[p.outcome]}: GET ${p.path} -> ${p.status ?? 'no response'} (${p.reason})`;
}
