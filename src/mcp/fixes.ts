/**
 * Non-interactive application of DeployReady's deterministic fixes. Shared by the MCP
 * `apply_safe_fixes` tool and `deployready analyze --fix`. Never asks anything, never uses AI.
 */
import * as path from 'path';
import { FileEditor } from '../agent/FileEditor';
import { FixManager } from '../agent/FixManager';
import { isNonScored } from '../analysis/ScoreCalculator';
import type { Finding } from '../types';

export interface FixOutcome {
  id: string;
  rule: string;
  title: string;
  file?: string;
  line?: number;
  message: string;
  backup: string | null;
}

export interface SafeFixResult {
  applied: FixOutcome[];
  skipped: FixOutcome[];
}

/** Findings a deterministic fix may be attempted for (scored, with a concrete safe fixer). */
export function fixableFindings(findings: Finding[]): Finding[] {
  return findings.filter((f) => !isNonScored(f) && FixManager.autoFixable(f));
}

export async function applySafeFixes(target: string, findings: Finding[]): Promise<SafeFixResult> {
  const root = path.resolve(target);
  const results = await FixManager.autoFixAll(fixableFindings(findings), new FileEditor(root));
  const out: SafeFixResult = { applied: [], skipped: [] };
  for (const r of results) {
    const f = r.finding;
    const row: FixOutcome = {
      id: f.id,
      rule: f.rule,
      title: f.title,
      file: f.file,
      line: f.line,
      message: r.message,
      backup: r.backup,
    };
    (r.applied ? out.applied : out.skipped).push(row);
  }
  return out;
}
