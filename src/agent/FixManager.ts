/**
 * Handles the fix flow for a single finding:
 *  - autoFix: safe, deterministic fixes applied directly (with backup).
 *  - aiSuggest/applySuggestion: model proposes a snippet rewrite; the SHELL
 *    shows the diff and gets explicit approval before applySuggestion runs.
 *
 * Safety: only ONE file is touched per approved fix; FileEditor always backs up.
 */
import { FileEditor } from './FileEditor';
import type { Snippet } from './FileEditor';
import { LINE_FIXERS, fixLine } from './lineFixers';
import type { ModelRouter, FixSuggestion } from '../ai/ModelRouter';
import type { Finding } from '../types';

export interface AutoFixResult {
  message: string;
  backup: string | null;
}

const AUTO_FIXABLE = new Set(['env-not-ignored']);

export class FixManager {
  /**
   * True if this finding has a safe, deterministic auto-fix candidate.
   * Line-based fixers are optimistic: the exact line may still not match the
   * fixable shape (e.g. an env-var TLS variant), in which case `autoFix` throws
   * and the caller falls back to the AI diff path.
   */
  static autoFixable(finding: Finding): boolean {
    if (AUTO_FIXABLE.has(finding.rule)) return true;
    return finding.rule in LINE_FIXERS && Boolean(finding.file && finding.line);
  }

  /** Apply a safe deterministic fix. Throws if the rule isn't auto-fixable. */
  static async autoFix(finding: Finding, editor: FileEditor): Promise<AutoFixResult> {
    if (finding.rule === 'env-not-ignored') {
      const existing = editor.fileExists('.gitignore') ? await editor.read('.gitignore') : '';
      if (/(^|\n)\s*\.env\s*($|\n)/.test(existing)) {
        return { message: '.gitignore already contains .env — no change needed.', backup: null };
      }
      const backup = await editor.appendLine('.gitignore', '.env');
      return {
        message: 'Added `.env` to .gitignore. NOTE: also remove it from git history and rotate any committed secrets.',
        backup,
      };
    }

    if (finding.rule in LINE_FIXERS) {
      if (!finding.file || !finding.line) {
        throw new Error(`Rule "${finding.rule}" needs a file+line to auto-fix.`);
      }
      const lines = (await editor.read(finding.file)).split('\n');
      const original = lines[finding.line - 1];
      if (original === undefined) throw new Error(`Line ${finding.line} not found in ${finding.file}.`);
      const fixed = fixLine(finding.rule, original);
      if (fixed === null) {
        throw new Error(`Could not safely auto-fix this occurrence of "${finding.rule}" — try \`fix\` for an AI diff.`);
      }
      const backup = await editor.replaceLines(finding.file, finding.line, finding.line, fixed);
      return { message: `Applied a safe fix to ${finding.file}:${finding.line}.`, backup };
    }

    throw new Error(`No automatic fix available for rule "${finding.rule}".`);
  }

  /** True if we can attempt an AI fix (finding points at a concrete file+line). */
  static aiFixable(finding: Finding): boolean {
    return Boolean(finding.file && finding.line);
  }

  /** Read the snippet around the finding for an AI rewrite. */
  static async snippetFor(finding: Finding, editor: FileEditor): Promise<Snippet> {
    if (!finding.file || !finding.line) throw new Error('This finding has no file/line to fix.');
    return editor.snippet(finding.file, finding.line);
  }

  /** Ask the model for a corrected snippet (sends the redacted snippet). */
  static async aiSuggest(finding: Finding, snippet: Snippet, router: ModelRouter): Promise<FixSuggestion> {
    return router.suggestFix(finding, snippet.text);
  }

  /** Apply an approved suggestion to disk (backs up first). Returns backup path. */
  static async applySuggestion(
    finding: Finding,
    snippet: Snippet,
    newCode: string,
    editor: FileEditor,
  ): Promise<string> {
    if (!finding.file) throw new Error('This finding has no file to write.');
    return editor.replaceLines(finding.file, snippet.startLine, snippet.endLine, newCode);
  }
}
