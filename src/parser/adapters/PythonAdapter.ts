/**
 * Lightweight Python parser for the MVP. Uses bounded line-based heuristics
 * (no native tree-sitter) to extract imports and Flask/FastAPI route decorators.
 * Good enough to map architecture; full AST fidelity is a Phase 2 upgrade.
 */
import type { ParserAdapter, ParseResult, RouteHit } from './ParserAdapter';

const IMPORT_RE = /^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))/;
// @app.get("/x"), @router.post("/y"), @app.route("/z", methods=["POST"])
const ROUTE_RE = /@\s*(\w+)\.(get|post|put|patch|delete|route)\s*\(\s*['"]([^'"]+)['"]/i;
const DEF_RE = /^\s*def\s+(\w+)\s*\(/;

export class PythonAdapter implements ParserAdapter {
  readonly extensions = new Set(['.py']);

  parse(_relPath: string, source: string): ParseResult {
    const imports = new Set<string>();
    const exports = new Set<string>();
    const routes: RouteHit[] = [];

    const lines = source.split('\n');
    lines.forEach((line, idx) => {
      if (line.length > 2000) return; // skip pathological lines

      const imp = IMPORT_RE.exec(line);
      if (imp) imports.add(imp[1] ?? imp[2] ?? '');

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

      const def = DEF_RE.exec(line);
      if (def && def[1]) exports.add(def[1]);
    });

    // Sub-router prefix composition (FastAPI include_router) is a future upgrade.
    return { imports: [...imports], exports: [...exports], routes, mounts: [] };
  }
}
