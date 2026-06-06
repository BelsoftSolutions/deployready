/**
 * Phase 1.5 — Safe file read/backup/write for agentic fix application.
 *
 * Safety contract (must be honored when implemented):
 * - Always write a timestamped backup before modifying a file.
 * - Confine all writes to the scanned project root (no traversal).
 * - Apply exactly one file change per approved fix.
 *
 * Stubbed for the MVP: the tool never edits user code yet.
 */
import * as fs from 'fs/promises';
import * as path from 'path';

export class FileEditor {
  constructor(private readonly projectRoot: string) {}

  /** Read a file within the project root. */
  async read(relPath: string): Promise<string> {
    return fs.readFile(this.resolveSafe(relPath), 'utf8');
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

  /** Phase 1.5: backup + write. Intentionally not implemented in the MVP. */
  async applyChange(_relPath: string, _oldCode: string, _newCode: string): Promise<never> {
    throw new Error('Agentic fix application ships in Phase 1.5. For now, apply fixes manually.');
  }
}
