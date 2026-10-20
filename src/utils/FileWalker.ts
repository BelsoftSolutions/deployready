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
import { isIgnored, parseGitignore, type IgnoreRule, type IgnoreScope } from './GitIgnore';

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

const WORKFLOW_EXTS = new Set(['.yml', '.yaml']);

const SOURCE_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.php', '.sql']);

/** Config-like files we want to inspect even though they aren't "source". */
const EXTRA_FILES = new Set([
  '.gitignore', // needed so the env-not-ignored check can see ignore rules
  'package.json',
  'requirements.txt',
  'composer.json',
  'Dockerfile',
  'next.config.js',
  'next.config.mjs',
]);

const ENV_TEMPLATES = new Set(['.env.example', '.env.sample', '.env.template']);

/** `.env` or any `.env.<suffix>` (staging, development, local, ...). */
export function isEnvFile(name: string): boolean {
  return name === '.env' || name.startsWith('.env.');
}

/** Committed-by-design placeholder env files; not secrets, never reported as committed. */
export function isEnvTemplate(name: string): boolean {
  return ENV_TEMPLATES.has(name);
}

const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2 MB — skip larger (generated/minified) files
const MAX_FILES = 20000; // cap for very large monorepos; keeps the scan bounded

export interface WalkedFile {
  /** Absolute path on disk. */
  absPath: string;
  /** Path relative to the scanned root (used in all reporting). */
  relPath: string;
  size: number;
}

const SPEC_FILE = /^(openapi|swagger)\.(json|ya?ml)$/i;

/** `openapi.{json,yaml,yml}` / `swagger.{json,yaml,yml}`: the project's own API description. */
export function isSpecFileName(name: string): boolean {
  return SPEC_FILE.test(name);
}

export interface WalkResult {
  files: WalkedFile[];
  /** OpenAPI/Swagger files (kept apart from `files` so source scanners never see them). */
  specFiles: WalkedFile[];
  /** Spec files seen but not readable (e.g. over the size cap), with the reason. */
  skippedSpecs: { relPath: string; reason: string }[];
  /** Files and directories skipped because a .gitignore rule matched them. */
  ignoredCount: number;
}

export class FileWalker {
  /**
   * Walk `root` and return source + relevant config files.
   * @throws if the path does not exist or is not a directory.
   */
  static async walk(root: string): Promise<WalkedFile[]> {
    return (await FileWalker.walkWithStats(root)).files;
  }

  /** Like `walk`, also reporting how many paths were skipped because of .gitignore rules. */
  static async walkWithStats(root: string): Promise<WalkResult> {
    const realRoot = await FileWalker.resolveRoot(root);
    const result: WalkResult = { files: [], specFiles: [], skippedSpecs: [], ignoredCount: 0 };
    await FileWalker.walkDir(realRoot, '', realRoot, result, []);
    return result;
  }

  /** Resolve `root` to its real directory path, with one-line errors fit to print as-is. */
  static async resolveRoot(root: string): Promise<string> {
    let realRoot: string;
    try {
      realRoot = await fs.realpath(path.resolve(root));
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT' || code === 'ENOTDIR') throw new Error(`Path not found: ${root}`);
      throw new Error(`Cannot access path: ${root}${code ? ` (${code})` : ''}`);
    }
    let isDir = false;
    try {
      isDir = (await fs.stat(realRoot)).isDirectory();
    } catch {
      throw new Error(`Cannot access path: ${root}`);
    }
    if (!isDir) throw new Error(`Not a directory: ${root}`);
    return realRoot;
  }

  private static async walkDir(
    dir: string,
    relDir: string,
    realRoot: string,
    result: WalkResult,
    parentScopes: IgnoreScope[],
  ): Promise<void> {
    const out = result.files;
    if (out.length >= MAX_FILES) return;

    let entries: import('fs').Dirent[];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return; // Unreadable dir (permissions) — skip silently.
    }

    let scopes = parentScopes;
    if (entries.some((e) => e.name === '.gitignore' && e.isFile())) {
      const rules = await FileWalker.readIgnoreRules(path.join(dir, '.gitignore'));
      if (rules.length > 0) scopes = [...parentScopes, { base: relDir, rules }];
    }

    for (const entry of entries) {
      if (out.length >= MAX_FILES) return;
      const abs = path.join(dir, entry.name);
      const relPath = relDir ? `${relDir}/${entry.name}` : entry.name;

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (entry.name.startsWith('.git') && relPath !== '.github') continue;
        if (relDir === '.github' && entry.name !== 'workflows') continue;
        if (relDir === '.github/workflows') continue;
        if (relPath !== '.github' && relPath !== '.github/workflows' && isIgnored(scopes, relPath, true)) {
          result.ignoredCount++;
          continue;
        }
        await FileWalker.walkDir(abs, relPath, realRoot, result, scopes);
        continue;
      }

      if (!entry.isFile()) continue; // skip sockets, devices, etc.

      if (relDir === '.github') continue;
      const ext = path.extname(entry.name).toLowerCase();
      const inWorkflows = relDir === '.github/workflows';
      if (!inWorkflows && isSpecFileName(entry.name)) {
        await FileWalker.collectSpec(abs, relPath, realRoot, scopes, result);
        continue;
      }
      let protectedFromIgnore = inWorkflows;
      if (inWorkflows) {
        if (!WORKFLOW_EXTS.has(ext)) continue;
      } else {
        const isSource = SOURCE_EXTS.has(ext);
        const isExtra = EXTRA_FILES.has(entry.name) || isEnvFile(entry.name);
        if (!isSource && !isExtra) continue;
        protectedFromIgnore = isExtra;
      }

      if (!protectedFromIgnore && isIgnored(scopes, relPath, false)) {
        result.ignoredCount++;
        continue;
      }

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

  private static async collectSpec(
    abs: string,
    relPath: string,
    realRoot: string,
    scopes: IgnoreScope[],
    result: WalkResult,
  ): Promise<void> {
    if (isIgnored(scopes, relPath, false)) {
      result.ignoredCount++;
      return;
    }
    try {
      const real = await fs.realpath(abs);
      const rel = path.relative(realRoot, real);
      if (rel.startsWith('..') || path.isAbsolute(rel)) return;
      const size = (await fs.stat(real)).size;
      const relOut = rel.split(path.sep).join('/');
      if (size > MAX_FILE_BYTES) {
        result.skippedSpecs.push({ relPath: relOut, reason: 'larger than 2 MB' });
        return;
      }
      result.specFiles.push({ absPath: real, relPath: relOut, size });
    } catch {
      return;
    }
  }

  private static async readIgnoreRules(file: string): Promise<IgnoreRule[]> {
    try {
      const st = await fs.stat(file);
      if (st.size > MAX_FILE_BYTES) return [];
      return parseGitignore(await fs.readFile(file, 'utf8'));
    } catch {
      return [];
    }
  }

  /** Safely read a walked file's contents as UTF-8. */
  static async read(file: WalkedFile): Promise<string> {
    return fs.readFile(file.absPath, 'utf8');
  }
}
