/**
 * Recursively find source files within a project, confined to the project root.
 *
 * Safety: the walker resolves the real root and refuses to follow paths that
 * escape it (symlink / traversal protection), skips heavy/irrelevant dirs, and
 * enforces a per-file size cap so a huge file can't blow up memory or feed a
 * ReDoS-prone scanner.
 */
import * as fs from 'fs/promises';
import * as path from 'path';

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  'out',
  'coverage',
  'vendor',
  '__pycache__',
  '.venv',
  'venv',
  '.cache',
]);

const SOURCE_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.php', '.sql']);

/** Config-like files we want to inspect even though they aren't "source". */
const EXTRA_FILES = new Set([
  '.env',
  '.env.local',
  '.env.production',
  '.gitignore', // needed so the env-not-ignored check can see ignore rules
  'package.json',
  'requirements.txt',
  'composer.json',
  'Dockerfile',
  'next.config.js',
  'next.config.mjs',
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2 MB — skip larger (generated/minified) files
const MAX_FILES = 20000; // cap for very large monorepos; keeps the scan bounded

export interface WalkedFile {
  /** Absolute path on disk. */
  absPath: string;
  /** Path relative to the scanned root (used in all reporting). */
  relPath: string;
  size: number;
}

export class FileWalker {
  /**
   * Walk `root` and return source + relevant config files.
   * @throws if the path does not exist or is not a directory.
   */
  static async walk(root: string): Promise<WalkedFile[]> {
    const realRoot = await fs.realpath(path.resolve(root));
    const stat = await fs.stat(realRoot);
    if (!stat.isDirectory()) {
      throw new Error(`Not a directory: ${realRoot}`);
    }

    const results: WalkedFile[] = [];
    await FileWalker.walkDir(realRoot, realRoot, results);
    return results;
  }

  private static async walkDir(
    dir: string,
    realRoot: string,
    out: WalkedFile[],
  ): Promise<void> {
    if (out.length >= MAX_FILES) return;

    let entries: import('fs').Dirent[];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return; // Unreadable dir (permissions) — skip silently.
    }

    for (const entry of entries) {
      if (out.length >= MAX_FILES) return;
      const abs = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.git')) continue;
        await FileWalker.walkDir(abs, realRoot, out);
        continue;
      }

      if (!entry.isFile()) continue; // skip sockets, devices, etc.

      const ext = path.extname(entry.name).toLowerCase();
      const isSource = SOURCE_EXTS.has(ext);
      const isExtra = EXTRA_FILES.has(entry.name);
      if (!isSource && !isExtra) continue;

      try {
        // Confinement check: ensure the resolved real path stays under root.
        const real = await fs.realpath(abs);
        const rel = path.relative(realRoot, real);
        if (rel.startsWith('..') || path.isAbsolute(rel)) continue;

        const st = await fs.stat(real);
        if (st.size > MAX_FILE_BYTES) continue;

        out.push({ absPath: real, relPath: rel.split(path.sep).join('/'), size: st.size });
      } catch {
        continue;
      }
    }
  }

  /** Safely read a walked file's contents as UTF-8. */
  static async read(file: WalkedFile): Promise<string> {
    return fs.readFile(file.absPath, 'utf8');
  }
}
