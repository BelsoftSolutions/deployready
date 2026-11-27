/**
 * Safe file read/backup/write for interactive fix application.
 *
 * Safety contract (enforced here):
 * - Every write makes a timestamped backup of the original first, under
 *   <root>/.deployready/backups (never next to the source file).
 * - All access is confined to the scanned project root (no traversal/symlink escape).
 * - Edits are applied by line range (deterministic) — no fuzzy text matching.
 */
import * as fs from 'fs';
import * as fsp from 'fs/promises';
import * as path from 'path';
import { extractFixRange } from './context';

export interface Snippet {
  text: string;
  /** 1-based inclusive line range the snippet covers. */
  startLine: number;
  endLine: number;
  /** Import/require lines from the same file, READ-ONLY context (outside the replaced range). */
  imports?: string[];
}

export interface ReplacePreview {
  /** File content as read from disk. */
  original: string;
  /** Content `replaceLines` would write. */
  updated: string;
  /** The existing text of the lines being replaced (LF-joined). */
  replaced: string;
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
    const { lines } = splitText(await this.read(relPath));
    const start = Math.max(1, line - context);
    const end = Math.min(lineCount(lines), line + context);
    return { text: lines.slice(start - 1, end).join('\n'), startLine: start, endLine: end };
  }

  /**
   * The enclosing unit of `line` for an AI rewrite (function / def block / +-15 lines, capped at
   * ~120 lines), plus the file's import lines as read-only context. See ./context.
   */
  async fixContext(relPath: string, line: number): Promise<Snippet> {
    const content = await this.read(relPath);
    const { lines } = splitText(content);
    const r = extractFixRange(content, line, path.extname(relPath));
    const end = Math.min(r.endLine, lineCount(lines));
    return { text: lines.slice(r.startLine - 1, end).join('\n'), startLine: r.startLine, endLine: end, imports: r.imports };
  }

  /**
   * Replace lines [startLine..endLine] (1-based inclusive) with `newText`.
   * Backs up the original first. Returns the backup path.
   * The file's dominant line ending, BOM and trailing newline are preserved.
   */
  async replaceLines(relPath: string, startLine: number, endLine: number, newText: string): Promise<string> {
    const abs = this.resolveSafe(relPath);
    const raw = await fsp.readFile(abs);
    const { updated } = applyReplace(raw.toString('utf8'), startLine, endLine, newText);
    const backup = await this.backup(abs, raw);
    await fsp.writeFile(abs, updated, 'utf8');
    return backup;
  }

  /**
   * Compute what `replaceLines` would write, without touching the disk.
   * Throws if the line range is invalid for the file.
   */
  async previewReplaceLines(relPath: string, startLine: number, endLine: number, newText: string): Promise<ReplacePreview> {
    const original = await this.read(relPath);
    return { original, ...applyReplace(original, startLine, endLine, newText) };
  }

  /** Append a line to a file (creating it if absent), with backup if it exists. */
  async appendLine(relPath: string, line: string): Promise<string | null> {
    const abs = this.resolveSafe(relPath);
    let backup: string | null = null;
    let current = '';
    if (fs.existsSync(abs)) {
      const raw = await fsp.readFile(abs);
      backup = await this.backup(abs, raw);
      current = raw.toString('utf8');
    }
    const { bom, eol } = splitText(current);
    const body = current.slice(bom.length);
    const sep = body.length && !body.endsWith('\n') ? eol : '';
    await fsp.writeFile(abs, `${current}${sep}${line.replace(/\r?\n/g, eol)}${eol}`, 'utf8');
    return backup;
  }

  fileExists(relPath: string): boolean {
    try {
      return fs.existsSync(this.resolveSafe(relPath));
    } catch {
      return false;
    }
  }

  /**
   * Back up `abs` to <root>/.deployready/backups/<relpath>.<ts>.bak, keeping
   * the project tree clean. A `.deployready/.gitignore` of `*` keeps the
   * backups (which may hold secrets) out of version control.
   */
  private async backup(abs: string, contents: Buffer): Promise<string> {
    const realRoot = fs.realpathSync(this.projectRoot);
    const rel = path.relative(realRoot, abs);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const metaDir = this.resolveSafe(BACKUP_DIR);
    await fsp.mkdir(metaDir, { recursive: true });
    const ignoreFile = path.join(metaDir, '.gitignore');
    if (!fs.existsSync(ignoreFile)) await fsp.writeFile(ignoreFile, '*\n', 'utf8');
    const backup = this.resolveSafe(path.join(BACKUP_DIR, 'backups', `${rel}.${stamp}.bak`));
    await fsp.mkdir(path.dirname(backup), { recursive: true });
    await fsp.writeFile(backup, contents);
    return backup;
  }

  /** Resolve a path to its real location and ensure it stays inside the real project root. */
  private resolveSafe(relPath: string): string {
    if (relPath.includes('\0')) throw new Error('Refusing to access a path containing NUL bytes.');
    const abs = path.resolve(this.projectRoot, relPath);
    if (!isInside(this.projectRoot, abs)) throw new Error(`Refusing to access path outside project: ${relPath}`);
    const real = realpathAllowMissing(abs);
    if (!isInside(fs.realpathSync(this.projectRoot), real)) {
      throw new Error(`Refusing to access path outside project: ${relPath}`);
    }
    return real;
  }
}

/** Per-project scratch dir (relative to the project root) holding fix backups. */
export const BACKUP_DIR = '.deployready';

const BOM = '\uFEFF';

interface TextParts {
  bom: string;
  eol: string;
  lines: string[];
}

/** Split file text into lines, remembering its BOM and dominant line ending (LF wins ties). */
function splitText(content: string): TextParts {
  const bom = content.startsWith(BOM) ? BOM : '';
  const body = content.slice(bom.length);
  const crlf = (body.match(/\r\n/g) ?? []).length;
  const lf = (body.match(/\n/g) ?? []).length - crlf;
  return { bom, eol: crlf > lf ? '\r\n' : '\n', lines: body.split(/\r?\n/) };
}

function joinText(parts: TextParts, lines: string[]): string {
  return parts.bom + lines.join(parts.eol);
}

function applyReplace(content: string, startLine: number, endLine: number, newText: string): Omit<ReplacePreview, 'original'> {
  const parts = splitText(content);
  const count = lineCount(parts.lines);
  if (!Number.isInteger(startLine) || !Number.isInteger(endLine) || startLine < 1 || startLine > endLine || endLine > count) {
    throw new Error(`Invalid line range ${startLine}-${endLine} for a file with ${count} line(s).`);
  }
  const before = parts.lines.slice(0, startLine - 1);
  const after = parts.lines.slice(endLine);
  return {
    updated: joinText(parts, [...before, ...newText.split(/\r?\n/), ...after]),
    replaced: parts.lines.slice(startLine - 1, endLine).join('\n'),
  };
}

/** Number of real lines: a trailing newline does not start another line. */
function lineCount(lines: string[]): number {
  return lines.length > 0 && lines[lines.length - 1] === '' ? lines.length - 1 : lines.length;
}

function isInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
}

/** realpath that tolerates a missing tail: resolve the nearest existing ancestor and re-append the rest. */
function realpathAllowMissing(abs: string): string {
  const tail: string[] = [];
  let cur = abs;
  for (;;) {
    try {
      return path.join(fs.realpathSync(cur), ...tail);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    try {
      // lstat succeeding while realpath failed means a dangling symlink: its target is unknown, so refuse.
      fs.lstatSync(cur);
      throw new Error(`Refusing to access dangling symlink: ${cur}`);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    const parent = path.dirname(cur);
    if (parent === cur) throw new Error(`Cannot resolve path: ${abs}`);
    tail.unshift(path.basename(cur));
    cur = parent;
  }
}
