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
import { readOpenApiRoutes } from './openapi';
import { discoverNextRoutes } from './nextRoutes';
import { joinPath, normalizeRoutePath } from './pathUtil';
import type { CodeGraph, Route } from '../types';

export class CodeParser {
  private static adapters: ParserAdapter[] = [new BabelAdapter(), new PythonAdapter()];

  private static adapterFor(relPath: string): ParserAdapter | null {
    const ext = path.extname(relPath).toLowerCase();
    return CodeParser.adapters.find((a) => a.extensions.has(ext)) ?? null;
  }

  static async analyze(projectPath: string): Promise<CodeGraph> {
    const { files, specFiles, skippedSpecs, ignoredCount } = await FileWalker.walkWithStats(projectPath);

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
    const spec = await readOpenApiRoutes(specFiles, skippedSpecs);
    const notes: string[] = [];

    // NestJS: a global prefix, RouterModule or versioning changes every controller path; skip them rather than guess.
    const nestGlobal = parses.flatMap((p) => p.result.nestGlobalConfig ?? []);
    if (nestGlobal.length) {
      let dropped = 0;
      for (const p of parses) {
        const kept = p.result.routes.filter((r) => !r.nest);
        dropped += p.result.routes.length - kept.length;
        p.result.routes = kept;
      }
      if (dropped) {
        notes.push(`NestJS: skipped ${dropped} controller route(s) because the project calls ${[...new Set(nestGlobal)].join(', ')}, which changes their final URL path (not resolved).`);
      }
    }

    const next = await discoverNextRoutes(files);
    notes.push(...next.notes);
    const codeRoutes = CodeParser.addFileRoutes(CodeParser.composeRoutes(parses), next.routes);
    const routes = CodeParser.mergeSpecRoutes(codeRoutes, spec.routes);

    return {
      root: path.resolve(projectPath),
      stack,
      entryPoints,
      modules,
      routes,
      fileCount: parses.length,
      gitignoreSkipped: ignoredCount,
      ...(spec.specFiles.length ? { specFiles: spec.specFiles } : {}),
      ...(notes.length || spec.notes.length ? { discoveryNotes: [...notes, ...spec.notes] } : {}),
    };
  }

  /** Add file-system routes (Next.js) that no code route already covers; a code route with the same method and path, or ALL, wins. */
  private static addFileRoutes(code: Route[], fileRoutes: Route[]): Route[] {
    if (fileRoutes.length === 0) return code;
    const keys = new Set(code.map((r) => `${r.method.toUpperCase()} ${normalizeRoutePath(r.path)}`));
    const merged = [...code];
    for (const f of fileRoutes) {
      const np = normalizeRoutePath(f.path);
      if (keys.has(`${f.method} ${np}`) || keys.has(`ALL ${np}`)) continue;
      keys.add(`${f.method} ${np}`);
      merged.push(f);
    }
    return merged;
  }

  /**
   * Add routes declared in OpenAPI/Swagger files. When a code route has the same
   * method and normalized path it stays as is and gains the spec as extra
   * evidence; a code route with method ALL covers every spec method.
   */
  private static mergeSpecRoutes(code: Route[], spec: Route[]): Route[] {
    if (spec.length === 0) return code;
    const byKey = new Map<string, Route>();
    for (const r of code) {
      const key = `${r.method.toUpperCase()} ${normalizeRoutePath(r.path)}`;
      if (!byKey.has(key)) byKey.set(key, r);
    }
    const merged = [...code];
    for (const s of spec) {
      const np = normalizeRoutePath(s.path);
      const twin = byKey.get(`${s.method} ${np}`) ?? byKey.get(`ALL ${np}`);
      if (twin) {
        twin.specFiles = [...new Set([...(twin.specFiles ?? []), s.file, ...(s.specFiles ?? [])])];
        continue;
      }
      merged.push(s);
    }
    return merged;
  }

  /**
   * Compose full route paths by following `app.use(prefix, router)` mounts across
   * files. A router file's routes are emitted under every prefix it's mounted at
   * (e.g. routes/auth.js `/login` mounted at `/api/auth` -> `/api/auth/login`).
   * Files not mounted anywhere keep their paths as written. Handles routers
   * mounted inside routers via a small fixpoint. A mount applied through auth
   * middleware (`app.use('/api', auth, router)`) guards the router's routes; a
   * file reached through several mounts is guarded only if every path is. The
   * guard names seen along the mount chain are unioned into `Route.guardNames`.
   * A mount whose prefix the adapter could not read (`unresolved`) contributes
   * nothing: a file reachable only through such mounts emits no routes, so a
   * wrong path is never produced.
   */
  private static composeRoutes(parses: FileParse[]): Route[] {
    const known = new Set(parses.map((p) => p.relPath));

    // Build incoming mount edges: target file <- { from, prefix }.
    const incoming = new Map<
      string,
      { from: string; prefix: string; guarded: boolean; names: string[]; unresolved: boolean; overrides: boolean }[]
    >();
    for (const { relPath, result } of parses) {
      for (const m of result.mounts) {
        const target = CodeParser.resolveSpecifier(relPath, m.source, known);
        if (!target) continue;
        const list = incoming.get(target) ?? [];
        list.push({
          from: relPath,
          prefix: m.prefix,
          guarded: m.guarded === true,
          names: m.guardNames ?? [],
          unresolved: m.unresolved === true,
          overrides: m.overridesPrefix === true,
        });
        incoming.set(target, list);
      }
    }

    // Prefix -> guarded per file. Mounted files start empty (filled from edges);
    // unmounted files own their paths as written ('').
    const prefixes = new Map<string, Map<string, MountState>>();
    for (const { relPath } of parses) {
      prefixes.set(relPath, incoming.has(relPath) ? new Map() : new Map([['', { guarded: false, names: [] }]]));
    }

    // Mounted files whose every mount has an unreadable prefix (directly or through a dead parent).
    const dead = new Set<string>();
    // Files mounted with a Flask `url_prefix=` override: a blueprint's own prefix baked into its routes would be replaced, not added to.
    const overridden = new Set<string>();
    for (const [target, edges] of incoming) if (edges.some((e) => e.overrides)) overridden.add(target);

    // Fixpoint: propagate prefixes along mount chains. Bounded to avoid cycles.
    for (let iter = 0; iter < 50; iter++) {
      let changed = false;
      for (const [target, edges] of incoming) {
        const next = new Map<string, MountState>();
        for (const edge of edges) {
          if (edge.unresolved || dead.has(edge.from)) continue;
          const fromMap = prefixes.get(edge.from);
          const bases: [string, MountState][] =
            fromMap && fromMap.size ? [...fromMap] : [['', { guarded: false, names: [] }]];
          for (const [base, baseState] of bases) {
            const full = joinPath(base, edge.prefix);
            const guarded = baseState.guarded || edge.guarded;
            const names = [...new Set([...baseState.names, ...edge.names])];
            const prior = next.get(full);
            next.set(
              full,
              prior
                ? { guarded: prior.guarded && guarded, names: [...new Set([...prior.names, ...names])] }
                : { guarded, names },
            );
          }
        }
        const isDead = next.size === 0 && edges.some((e) => e.unresolved || dead.has(e.from));
        if (isDead !== dead.has(target)) {
          if (isDead) dead.add(target);
          else dead.delete(target);
          changed = true;
        }
        const cur = prefixes.get(target)!;
        const sameState = (a: MountState | undefined, b: MountState) =>
          a !== undefined && a.guarded === b.guarded && a.names.join('\0') === b.names.join('\0');
        if (next.size !== cur.size || [...next].some(([p, st]) => !sameState(cur.get(p), st))) {
          prefixes.set(target, next);
          changed = true;
        }
      }
      if (!changed) break;
    }

    // Emit routes under every prefix the owning file resolved to.
    const routes: Route[] = [];
    const seen = new Map<string, Route>();
    for (const { relPath, result } of parses) {
      if (dead.has(relPath)) continue;
      const ps = prefixes.get(relPath);
      const list: [string, MountState][] = ps && ps.size ? [...ps] : [['', { guarded: false, names: [] }]];
      for (const [p, mount] of list) {
        const mountGuarded = mount.guarded;
        for (const r of result.routes) {
          if (r.ownPrefix && overridden.has(relPath)) continue;
          const full = joinPath(p, r.path);
          const key = `${r.method} ${full} ${relPath}`;
          const guarded = r.guarded || mountGuarded;
          const prior = seen.get(key);
          if (prior) {
            prior.guarded = prior.guarded && guarded;
            const merged = [...new Set([...(prior.guardNames ?? []), ...mount.names, ...(r.guardNames ?? [])])];
            if (merged.length) prior.guardNames = merged;
            continue;
          }
          const route: Route = { method: r.method, path: full, file: relPath, line: r.line, guarded };
          const guardNames = [...new Set([...mount.names, ...(r.guardNames ?? [])])];
          if (guardNames.length) route.guardNames = guardNames;
          seen.set(key, route);
          routes.push(route);
        }
      }
    }
    return routes;
  }

  /**
   * Resolve a module specifier to a known project file, or null. Handles
   * relative JS/TS imports and (for Python) both relative and project-root
   * specifiers, trying common extensions and index/package files. Bare package
   * imports (e.g. "express") resolve to nothing.
   */
  private static resolveSpecifier(fromFile: string, spec: string, known: Set<string>): string | null {
    const baseDir = path.posix.dirname(fromFile);
    const rel = spec.startsWith('.') ? path.posix.normalize(path.posix.join(baseDir, spec)) : spec;
    const bases = spec.startsWith('.') ? [rel] : [rel, path.posix.normalize(path.posix.join(baseDir, spec))];
    for (const target of bases) {
      const candidates = [
        target,
        `${target}.js`,
        `${target}.ts`,
        `${target}.jsx`,
        `${target}.tsx`,
        `${target}.mjs`,
        `${target}.cjs`,
        `${target}.py`,
        `${target}/index.js`,
        `${target}/index.ts`,
        `${target}/__init__.py`,
      ];
      const hit = candidates.find((c) => known.has(c));
      if (hit) return hit;
    }
    return null;
  }

  private static async safeRead(file: WalkedFile): Promise<string | null> {
    try {
      return await FileWalker.read(file);
    } catch {
      return null;
    }
  }
}

interface MountState {
  guarded: boolean;
  names: string[];
}
