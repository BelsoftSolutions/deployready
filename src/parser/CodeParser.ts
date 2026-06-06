/**
 * Static analysis orchestrator. Walks the project, picks the right parser
 * adapter per file, builds the dependency graph, detects stack + entry points,
 * and assembles a CodeGraph.
 *
 * Interface contract (from spec):
 *   const graph = await CodeParser.analyze('/path/to/project');
 */
import * as path from 'path';
import { FileWalker } from '../utils/FileWalker';
import type { WalkedFile } from '../utils/FileWalker';
import { StackDetector } from './StackDetector';
import { EntryPointDetector } from './EntryPointDetector';
import { DependencyGraph } from './DependencyGraph';
import type { FileParse } from './DependencyGraph';
import { BabelAdapter } from './adapters/BabelAdapter';
import { PythonAdapter } from './adapters/PythonAdapter';
import type { ParserAdapter } from './adapters/ParserAdapter';
import type { CodeGraph, Route } from '../types';

export class CodeParser {
  private static adapters: ParserAdapter[] = [new BabelAdapter(), new PythonAdapter()];

  private static adapterFor(relPath: string): ParserAdapter | null {
    const ext = path.extname(relPath).toLowerCase();
    return CodeParser.adapters.find((a) => a.extensions.has(ext)) ?? null;
  }

  static async analyze(projectPath: string): Promise<CodeGraph> {
    const files = await FileWalker.walk(projectPath);

    const parses: FileParse[] = [];
    for (const file of files) {
      const adapter = CodeParser.adapterFor(file.relPath);
      if (!adapter) continue;

      const source = await CodeParser.safeRead(file);
      if (source === null) continue;

      parses.push({ relPath: file.relPath, result: adapter.parse(file.relPath, source) });
    }

    const stack = await StackDetector.detect(projectPath, files);
    const modules = DependencyGraph.build(parses);
    const entryPoints = EntryPointDetector.detect(files);
    const routes = CodeParser.composeRoutes(parses);

    return {
      root: path.resolve(projectPath),
      stack,
      entryPoints,
      modules,
      routes,
      fileCount: parses.length,
    };
  }

  /**
   * Compose full route paths by following `app.use(prefix, router)` mounts across
   * files. A router file's routes are emitted under every prefix it's mounted at
   * (e.g. routes/auth.js `/login` mounted at `/api/auth` -> `/api/auth/login`).
   * Files not mounted anywhere keep their paths as written. Handles routers
   * mounted inside routers via a small fixpoint.
   */
  private static composeRoutes(parses: FileParse[]): Route[] {
    const known = new Set(parses.map((p) => p.relPath));

    // Build incoming mount edges: target file <- { from, prefix }.
    const incoming = new Map<string, { from: string; prefix: string }[]>();
    for (const { relPath, result } of parses) {
      for (const m of result.mounts) {
        const target = CodeParser.resolveSpecifier(relPath, m.source, known);
        if (!target) continue;
        const list = incoming.get(target) ?? [];
        list.push({ from: relPath, prefix: m.prefix });
        incoming.set(target, list);
      }
    }

    // Prefix sets per file. Mounted files start empty (filled from edges);
    // unmounted files own their paths as written ('').
    const prefixes = new Map<string, Set<string>>();
    for (const { relPath } of parses) {
      prefixes.set(relPath, incoming.has(relPath) ? new Set() : new Set(['']));
    }

    // Fixpoint: propagate prefixes along mount chains. Bounded to avoid cycles.
    for (let iter = 0; iter < 50; iter++) {
      let changed = false;
      for (const [target, edges] of incoming) {
        const next = new Set<string>();
        for (const edge of edges) {
          const fromSet = prefixes.get(edge.from);
          const bases = fromSet && fromSet.size ? [...fromSet] : [''];
          for (const base of bases) next.add(joinPath(base, edge.prefix));
        }
        const cur = prefixes.get(target)!;
        if (next.size !== cur.size || [...next].some((p) => !cur.has(p))) {
          prefixes.set(target, next);
          changed = true;
        }
      }
      if (!changed) break;
    }

    // Emit routes under every prefix the owning file resolved to.
    const routes: Route[] = [];
    const seen = new Set<string>();
    for (const { relPath, result } of parses) {
      const ps = prefixes.get(relPath);
      const list = ps && ps.size ? [...ps] : [''];
      for (const p of list) {
        for (const r of result.routes) {
          const full = joinPath(p, r.path);
          const key = `${r.method} ${full} ${relPath}`;
          if (seen.has(key)) continue;
          seen.add(key);
          routes.push({ method: r.method, path: full, file: relPath, line: r.line, guarded: r.guarded });
        }
      }
    }
    return routes;
  }

  /** Resolve a relative module specifier to a known project file, or null. */
  private static resolveSpecifier(fromFile: string, spec: string, known: Set<string>): string | null {
    if (!spec.startsWith('.')) return null;
    const baseDir = path.posix.dirname(fromFile);
    const target = path.posix.normalize(path.posix.join(baseDir, spec));
    const candidates = [
      target,
      `${target}.js`,
      `${target}.ts`,
      `${target}.jsx`,
      `${target}.tsx`,
      `${target}.mjs`,
      `${target}.cjs`,
      `${target}/index.js`,
      `${target}/index.ts`,
    ];
    return candidates.find((c) => known.has(c)) ?? null;
  }

  private static async safeRead(file: WalkedFile): Promise<string | null> {
    try {
      return await FileWalker.read(file);
    } catch {
      return null;
    }
  }
}

/** Join a mount prefix and a route path into a single normalized URL path. */
function joinPath(base: string, sub: string): string {
  let combined = `${base || ''}/${sub || ''}`.replace(/\/{2,}/g, '/');
  if (combined.length > 1) combined = combined.replace(/\/$/, '');
  if (!combined.startsWith('/')) combined = `/${combined}`;
  return combined;
}
