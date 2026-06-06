/**
 * Safe file read/backup/write for interactive fix application.
 *
 * Safety contract (enforced here):
 * - Every write makes a timestamped backup of the original first.
 * - All access is confined to the scanned project root (no traversal/symlink escape).
 * - Edits are applied by line range (deterministic) — no fuzzy text matching.
 */
import * as fs from 'fs';
import * as fsp from 'fs/promises';
import * as path from 'path';

export interface Snippet {
  text: string;
  /** 1-based inclusive line range the snippet covers. */
  startLine: number;
  endLine: number;
}

export class FileEditor {
  constructor(private readonly projectRoot: string) {}

  /** Read a file within the project root. */
  async read(relPath: string): Promise<string> {
    return fsp.readFile(this.resolveSafe(relPath), 'utf8');
  }

  /**
   * Extract the line at `line` (1-based) plus `context` lines on each side.
   * Returns the exact text and the line range it spans.
   */
  async snippet(relPath: string, line: number, context = 3): Promise<Snippet> {
    const lines = (await this.read(relPath)).split('\n');
    const start = Math.max(1, line - context);
    const end = Math.min(lines.length, line + context);
    return { text: lines.slice(start - 1, end).join('\n'), startLine: start, endLine: end };
  }

  /**
   * Replace lines [startLine..endLine] (1-based inclusive) with `newText`.
   * Backs up the original first. Returns the backup path.
   */
  async replaceLines(relPath: string, startLine: number, endLine: number, newText: string): Promise<string> {
    const abs = this.resolveSafe(relPath);
    const original = await fsp.readFile(abs, 'utf8');
    const backup = await this.backup(abs, original);

    const lines = original.split('\n');
    const before = lines.slice(0, startLine - 1);
    const after = lines.slice(endLine);
    const updated = [...before, ...newText.split('\n'), ...after].join('\n');
    await fsp.writeFile(abs, updated, 'utf8');
    return backup;
  }

  /** Append a line to a file (creating it if absent), with backup if it exists. */
  async appendLine(relPath: string, line: string): Promise<string | null> {
    const abs = this.resolveSafe(relPath);
    let backup: string | null = null;
    let current = '';
    if (fs.existsSync(abs)) {
      current = await fsp.readFile(abs, 'utf8');
      backup = await this.backup(abs, current);
    }
    const sep = current.length && !current.endsWith('\n') ? '\n' : '';
    await fsp.writeFile(abs, `${current}${sep}${line}\n`, 'utf8');
    return backup;
  }

  fileExists(relPath: string): boolean {
    try {
      return fs.existsSync(this.resolveSafe(relPath));
    } catch {
      return false;
    }
  }

  private async backup(abs: string, contents: string): Promise<string> {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backup = `${abs}.bak.${stamp}`;
    await fsp.writeFile(backup, contents, 'utf8');
    return backup;
  }

  /** Resolve a path and ensure it stays inside the project root. */
  private resolveSafe(relPath: string): string {
    const abs = path.resolve(this.projectRoot, relPath);
    const rel = path.relative(this.projectRoot, abs);
    if (rel.startsWith('..') || path.isAbsolute(rel)) {
      throw new Error(`Refusing to access path outside project: ${relPath}`);
    }
    return abs;
  }
}
