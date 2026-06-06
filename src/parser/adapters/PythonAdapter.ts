/**
 * Python parser for the MVP. Bounded line-based heuristics (no native
 * tree-sitter) that cover the common real-world shapes:
 *  - imports (incl. binding names to modules for mount resolution)
 *  - Flask/FastAPI route decorators (@app.get, @router.post, @app.route)
 *  - FastAPI sub-router mounts (app.include_router(x, prefix="/p"))
 *
 * Full AST fidelity is a Phase 2 upgrade.
 */
import type { ParserAdapter, ParseResult, RouteHit, MountHit } from './ParserAdapter';

const FROM_IMPORT_RE = /^\s*from\s+([.\w]+)\s+import\s+(.+)$/;
const IMPORT_RE = /^\s*import\s+([.\w]+)(?:\s+as\s+(\w+))?/;
const ROUTE_RE = /@\s*(\w+)\.(get|post|put|patch|delete|route)\s*\(\s*['"]([^'"]+)['"]/i;
const INCLUDE_RE = /\.include_router\s*\(\s*([\w.]+)([^)]*)\)/;
const PREFIX_RE = /prefix\s*=\s*['"]([^'"]+)['"]/;
const DEF_RE = /^\s*def\s+(\w+)\s*\(/;

/** Convert a dotted Python module spec into a path fragment the resolver understands. */
function moduleToPath(mod: string): string {
  const m = /^(\.*)(.*)$/.exec(mod)!;
  const dots = m[1]!.length;
  const body = (m[2] ?? '').replace(/\./g, '/');
  if (dots === 0) return body; // absolute (project-root relative)
  if (dots === 1) return `./${body}`; // current package
  return '../'.repeat(dots - 1) + body; // parent packages
}

export class PythonAdapter implements ParserAdapter {
  readonly extensions = new Set(['.py']);

  parse(_relPath: string, source: string): ParseResult {
    const imports = new Set<string>();
    const exports = new Set<string>();
    const routes: RouteHit[] = [];
    const mounts: MountHit[] = [];
    // local name -> candidate module path fragments (submodule + module forms).
    const bindings = new Map<string, string[]>();

    const lines = source.split('\n');
    lines.forEach((line, idx) => {
      if (line.length > 2000) return;

      const from = FROM_IMPORT_RE.exec(line);
      if (from) {
        const mod = from[1]!;
        imports.add(mod);
        for (const raw of from[2]!.split(',')) {
          const part = raw.trim().replace(/[()]/g, '');
          if (!part || part === '*') continue;
          const [name, , alias] = part.split(/\s+/);
          const bound = alias || name;
          if (!bound) continue;
          const submodule = mod.endsWith('.') ? `${mod}${name}` : `${mod}.${name}`;
          bindings.set(bound, [moduleToPath(submodule), moduleToPath(mod)]);
        }
      }

      const imp = IMPORT_RE.exec(line);
      if (imp && !from) {
        imports.add(imp[1]!);
        const alias = imp[2];
        const bound = alias || imp[1]!.split('.')[0]!;
        bindings.set(bound, [moduleToPath(imp[1]!)]);
        if (!alias) bindings.set(imp[1]!, [moduleToPath(imp[1]!)]);
      }

      const route = ROUTE_RE.exec(line);
      if (route) {
        const verb = route[2]!.toLowerCase();
        routes.push({
          method: verb === 'route' ? 'ALL' : verb.toUpperCase(),
          path: route[3]!,
          line: idx + 1,
          guarded: /depends|require|auth|login_required/i.test(line),
        });
      }

      const inc = INCLUDE_RE.exec(line);
      if (inc) {
        const arg = inc[1]!;
        const prefix = PREFIX_RE.exec(inc[2] ?? '')?.[1] ?? '';
        for (const c of PythonAdapter.resolveArg(arg, bindings)) {
          mounts.push({ prefix, source: c });
        }
      }

      const def = DEF_RE.exec(line);
      if (def && def[1]) exports.add(def[1]);
    });

    return { imports: [...imports], exports: [...exports], routes, mounts };
  }

  /** Map an include_router argument (e.g. `auth.router`) to candidate file paths. */
  private static resolveArg(arg: string, bindings: Map<string, string[]>): string[] {
    const parts = arg.split('.');
    // Try progressively shorter dotted prefixes: auth.router -> auth.
    for (let i = parts.length; i >= 1; i--) {
      const key = parts.slice(0, i).join('.');
      const hit = bindings.get(key);
      if (hit) return hit;
    }
    return [];
  }
}
