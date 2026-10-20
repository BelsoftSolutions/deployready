/**
 * Next.js file-system routes. No AST: the folder layout is the evidence.
 *
 *   app/**\/route.ts|js   -> one route per exported HTTP method (GET, POST, ...)
 *   app/**\/page.tsx|jsx  -> GET
 *   pages/api/**          -> method ALL (a default-exported handler answers any verb)
 *
 * A directory counts as a Next app only when its package.json depends on `next`.
 * `(group)` segments are removed from the URL; `[id]` segments are kept and are
 * path parameters (EndpointMapper skips them). Private (`_x`), parallel (`@slot`)
 * and intercepting (`(.)x`) folders are skipped, never guessed. A `basePath`
 * that is not a string literal skips every file route of that app, with a note.
 * Guard evidence is never inferred here (middleware.ts matchers stay unread), so
 * every file route is unguarded: the conservative reading.
 */
import * as path from 'path';
import { FileWalker } from '../utils/FileWalker';
import type { WalkedFile } from '../utils/FileWalker';
import { joinPath } from './pathUtil';
import type { Route } from '../types';

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const CODE_EXT = /\.(?:tsx?|jsx?|mjs)$/;

export interface NextDiscovery {
  routes: Route[];
  notes: string[];
}

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').replace(/\s\/\/.*$/gm, '');
}

/** HTTP methods a route handler module exports. */
export function exportedMethods(source: string): string[] {
  const src = stripComments(source);
  const found = new Set<string>();
  const add = (name: string | undefined): void => {
    if (name && HTTP_METHODS.has(name)) found.add(name);
  };
  for (const m of src.matchAll(/\bexport\s+(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/g)) add(m[1]);
  for (const m of src.matchAll(/\bexport\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g)) add(m[1]);
  for (const m of src.matchAll(/\bexport\s+(?:const|let|var)\s*\{([^}]*)\}/g)) {
    for (const part of m[1]!.split(',')) add(part.split(':').pop()?.split('=')[0]?.trim());
  }
  for (const m of src.matchAll(/\bexport\s*\{([^}]*)\}/g)) {
    for (const part of m[1]!.split(',')) add(part.trim().split(/\s+as\s+/).pop()?.trim());
  }
  return [...found];
}

function hasDefaultExport(source: string): boolean {
  const src = stripComments(source);
  return /\bexport\s+default\b/.test(src) || /\bmodule\.exports\b/.test(src) || /\bexport\s*\{[^}]*\bas\s+default\b/.test(src);
}

type Segments = string[] | null;

/** URL segments for a folder path inside the app router, or null when a segment makes the URL unknowable. */
function appSegments(dirs: string[]): Segments {
  const out: string[] = [];
  for (const d of dirs) {
    if (d.startsWith('(.')) return null; // intercepting route: (.)x, (..)x, (...)x
    if (/^\(.+\)$/.test(d)) continue; // route group: not part of the URL
    if (d.startsWith('_') || d.startsWith('@')) return null; // private folder / parallel slot
    out.push(d);
  }
  return out;
}

function toPath(base: string, segments: string[]): string {
  return joinPath(base, segments.join('/'));
}

/** `basePath` of a Next app: '' when absent, the literal when readable, null when it is computed. */
async function readBasePath(configs: WalkedFile[]): Promise<string | null> {
  for (const cfg of configs) {
    let text: string;
    try {
      text = stripComments(await FileWalker.read(cfg));
    } catch {
      continue;
    }
    const m = /\bbasePath\b\s*:?\s*([^,}\n]*)/.exec(text);
    if (!m) continue;
    const lit = /^\s*(['"`])(\/[^'"`$]*)\1\s*$/.exec(m[1]!);
    if (lit) return lit[2]!.replace(/\/+$/, '');
    return null;
  }
  return '';
}

export async function discoverNextRoutes(files: WalkedFile[]): Promise<NextDiscovery> {
  const routes: Route[] = [];
  const notes: string[] = [];
  const byRel = new Map(files.map((f) => [f.relPath, f]));

  for (const pkg of files) {
    if (path.posix.basename(pkg.relPath) !== 'package.json') continue;
    let json: { dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown> };
    try {
      json = JSON.parse(await FileWalker.read(pkg));
    } catch {
      continue;
    }
    if (!json || typeof json !== 'object' || !(json.dependencies?.next ?? json.devDependencies?.next)) continue;

    const root = path.posix.dirname(pkg.relPath);
    const at = (rel: string): string => (root === '.' ? rel : `${root}/${rel}`);
    const configs = ['next.config.js', 'next.config.mjs', 'next.config.cjs', 'next.config.ts']
      .map((n) => byRel.get(at(n)))
      .filter((f): f is WalkedFile => f !== undefined);

    // Next uses the root-level folder when it exists, otherwise src/: never both.
    const hasFiles = (dir: string): boolean => files.some((f) => f.relPath.startsWith(`${dir}/`));
    const active: { dir: string; kind: 'app' | 'pages' }[] = [];
    for (const kind of ['app', 'pages'] as const) {
      const dir = [at(kind), at(`src/${kind}`)].find(hasFiles);
      if (dir) active.push({ dir, kind });
    }
    if (active.length === 0) continue;

    const basePath = await readBasePath(configs);
    if (basePath === null) {
      notes.push(`Next.js file routes in ${root === '.' ? 'the project root' : root} skipped: next.config sets a basePath that is not a string literal.`);
      continue;
    }

    for (const { dir, kind } of active) {
      for (const file of files) {
        if (!file.relPath.startsWith(`${dir}/`)) continue;
        const inner = file.relPath.slice(dir.length + 1).split('/');
        const base = inner[inner.length - 1]!;
        if (!CODE_EXT.test(base) || /\.d\.ts$/.test(base) || /\.(?:test|spec)\./.test(base)) continue;
        const stem = base.replace(CODE_EXT, '');
        const dirs = inner.slice(0, -1);

        let source: string;
        try {
          source = await FileWalker.read(file);
        } catch {
          continue;
        }

        if (kind === 'app') {
          if (stem !== 'route' && stem !== 'page') continue;
          const segs = appSegments(dirs);
          if (!segs) continue;
          const urlPath = toPath(basePath, segs);
          if (stem === 'page') {
            if (hasDefaultExport(source)) routes.push({ method: 'GET', path: urlPath, file: file.relPath, guarded: false });
          } else {
            for (const method of exportedMethods(source)) routes.push({ method, path: urlPath, file: file.relPath, guarded: false });
          }
        } else {
          if (dirs[0] !== 'api' || !hasDefaultExport(source)) continue;
          const segs = stem === 'index' ? dirs : [...dirs, stem];
          routes.push({ method: 'ALL', path: toPath(basePath, segs), file: file.relPath, guarded: false });
        }
      }
    }
  }
  return { routes, notes };
}
