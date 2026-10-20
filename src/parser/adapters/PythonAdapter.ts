/**
 * Python parser for the MVP. Bounded line-based heuristics (no native
 * tree-sitter) that cover the common real-world shapes:
 *  - imports (incl. binding names to modules for mount resolution)
 *  - Flask/FastAPI route decorators (@app.get, @router.post, @app.route)
 *  - FastAPI sub-router mounts (app.include_router(x, prefix="/p")) and
 *    APIRouter(prefix=...), Flask register_blueprint(bp, url_prefix=...) and
 *    Blueprint(..., url_prefix=...)
 *
 * A prefix is only used when it is a string literal or a same-file top-level
 * constant; anything else (settings, f-strings, imports) marks the mount
 * unresolved so its routes are skipped, never guessed.
 *
 * Full AST fidelity is a Phase 2 upgrade.
 */
import type { ParserAdapter, ParseResult, RouteHit, MountHit } from './ParserAdapter';
import { joinPath } from '../pathUtil';
import { isPyAuthDependency, isPyGuardDecorator } from './authMiddleware';

const FROM_IMPORT_RE = /^\s*from\s+([.\w]+)\s+import\s+(.+)$/;
const IMPORT_RE = /^\s*import\s+([.\w]+)(?:\s+as\s+(\w+))?/;
const ROUTE_RE = /@\s*(\w+)\.(get|post|put|patch|delete|route)\s*\(\s*['"]([^'"]+)['"]/i;
const REGISTER_RE = /([\w.]*\w)\.(include_router|register_blueprint)\s*\(/;
const ROUTER_DEF_RE = /^\s*(\w+)\s*(?::[^=]+)?=\s*(?:[\w.]+\.)?(APIRouter|Blueprint|FastAPI)\s*\(/;
const CONST_RE = /^([A-Za-z_]\w*)\s*(?::[^=]+?)?=\s*(['"])((?:(?!\2)[^\\\n])*)\2\s*(?:#.*)?$/;
const TOP_ASSIGN_RE = /^([A-Za-z_]\w*)\s*(?::[^=]*)?(?:[-+*/%|&^@]|\/\/|\*\*|<<|>>)?=(?!=)/;
const KWARG_RE = /^([A-Za-z_]\w*)\s*=(?!=)\s*([\s\S]*)$/;
const MAX_CALL_LINES = 40;
const DEPENDS_RE = /\b(?:Depends|Security)\s*\(/g;
const PY_NON_NAMES = new Set(['True', 'False', 'None']);
const DEF_RE = /^\s*def\s+(\w+)\s*\(/;
const MAX_DECORATOR_LINES = 12;

/** Identifiers and string-literal words inside each `Depends(...)` / `Security(...)` call of a text. */
function dependsCalls(line: string): { ids: string[]; strings: string[] }[] {
  const calls: { ids: string[]; strings: string[] }[] = [];
  for (const m of line.matchAll(DEPENDS_RE)) {
    let depth = 1;
    let i = m.index! + m[0].length;
    const start = i;
    for (; i < line.length && depth > 0; i++) {
      if (line[i] === '(') depth++;
      else if (line[i] === ')') depth--;
    }
    const inner = line.slice(start, depth === 0 ? i - 1 : i);
    const strings = [...inner.matchAll(/(['"])([^'"]*)\1/g)].map((s) => s[2]!).filter(Boolean);
    const bare = inner.replace(/(['"])[^'"]*\1/g, ' ').replace(/\b\w+\s*=(?!=)/g, ' ');
    const ids: string[] = [];
    for (const id of bare.match(/[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*/g) ?? []) {
      const last = id.split('.').pop()!;
      if (!PY_NON_NAMES.has(last)) ids.push(last);
    }
    calls.push({ ids, strings });
  }
  return calls;
}

/** Identifiers (and string-literal words) inside every `Depends(...)` call on a line. */
function dependsNames(line: string): string[] {
  return [...new Set(dependsCalls(line).flatMap((c) => [...c.ids, ...c.strings]))];
}

interface GuardEvidence {
  guarded: boolean;
  names: string[];
}

const NO_GUARD: GuardEvidence = { guarded: false, names: [] };

function mergeGuards(...parts: GuardEvidence[]): GuardEvidence {
  return { guarded: parts.some((p) => p.guarded), names: [...new Set(parts.flatMap((p) => p.names))] };
}

/** Auth evidence in a `dependencies=[Depends(get_current_user)]` value: only dependencies that check the caller count (`get_db` does not). */
function authDependencies(text: string | undefined): GuardEvidence {
  if (!text) return NO_GUARD;
  const names: string[] = [];
  for (const c of dependsCalls(text)) {
    const auth = c.ids.filter(isPyAuthDependency);
    if (auth.length) names.push(...auth, ...c.strings);
  }
  return names.length ? { guarded: true, names: [...new Set(names)] } : NO_GUARD;
}

/** Net `(` minus `)` outside string literals. */
function parenBalance(text: string): number {
  let balance = 0;
  let quote = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = '';
    } else if (ch === '#') {
      break;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '(') {
      balance++;
    } else if (ch === ')') {
      balance--;
    }
  }
  return balance;
}

/**
 * Guard decorators stacked under a route decorator (Flask `@login_required`,
 * `@admin_required`, `@jwt_required()`, `@roles_required('admin')`). Reads the
 * `@...` lines directly below line `idx`; stops at the first line that is not
 * a decorator. A decorator above the route decorator does not guard it.
 */
function stackedGuards(lines: string[], idx: number): GuardEvidence {
  const names: string[] = [];
  let pending = '';
  let balance = 0;
  for (let j = idx + 1; j < lines.length && j <= idx + MAX_DECORATOR_LINES; j++) {
    const text = lines[j]!.trim();
    if (balance > 0) {
      pending += ` ${text}`;
      balance += parenBalance(text);
    } else {
      if (!text || text.startsWith('#')) continue;
      if (!text.startsWith('@')) break;
      pending = text;
      balance = parenBalance(text);
    }
    if (balance > 0) continue;
    const m = /^@\s*([\w.]+)\s*(?:\(([\s\S]*)\))?/.exec(pending);
    pending = '';
    if (!m) continue;
    const name = m[1]!.split('.').pop()!;
    const args = m[2] ?? '';
    if (!isPyGuardDecorator(name) || /\boptional\s*=\s*True\b/.test(args)) continue;
    names.push(name, ...[...args.matchAll(/(['"])([^'"]+)\1/g)].map((s) => s[2]!));
  }
  return names.length ? { guarded: true, names: [...new Set(names)] } : NO_GUARD;
}

/** Convert a dotted Python module spec into a path fragment the resolver understands. */
function moduleToPath(mod: string): string {
  const m = /^(\.*)(.*)$/.exec(mod)!;
  const dots = m[1]!.length;
  const body = (m[2] ?? '').replace(/\./g, '/');
  if (dots === 0) return body; // absolute (project-root relative)
  if (dots === 1) return `./${body}`; // current package
  return '../'.repeat(dots - 1) + body; // parent packages
}

/** Text between the parentheses of the call whose `(` is at `col` of line `idx` (may span lines), or null if unbalanced. */
function extractCall(lines: string[], idx: number, col: number): string | null {
  let depth = 0;
  let quote = '';
  let out = '';
  for (let l = idx; l < lines.length && l < idx + MAX_CALL_LINES; l++) {
    const text = lines[l]!;
    for (let i = l === idx ? col : 0; i < text.length; i++) {
      const ch = text[i]!;
      if (quote) {
        if (ch === '\\') i++;
        else if (ch === quote) quote = '';
      } else if (ch === '#') {
        break;
      } else if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === '(') {
        depth++;
        if (depth === 1) continue;
      } else if (ch === ')') {
        depth--;
        if (depth === 0) return out;
      }
      if (depth >= 1) out += ch;
    }
    quote = '';
    out += ' ';
  }
  return null;
}

/** Split call arguments on top-level commas. */
function splitArgs(inner: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote = '';
  let cur = '';
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i]!;
    if (quote) {
      cur += ch;
      if (ch === '\\') cur += inner[++i] ?? '';
      else if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) depth--;
    else if (ch === ',' && depth === 0) {
      parts.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

interface PyCall {
  positional: string[];
  kwargs: Map<string, string>;
}

function parseCall(inner: string): PyCall {
  const positional: string[] = [];
  const kwargs = new Map<string, string>();
  for (const part of splitArgs(inner)) {
    const kw = KWARG_RE.exec(part);
    if (kw) kwargs.set(kw[1]!, kw[2]!.trim());
    else positional.push(part);
  }
  return { positional, kwargs };
}

/** A plain "..." / '...' literal, or a bare same-file constant name; null for anything else (f-strings, settings.X, concatenation). */
function pyString(text: string, consts: Map<string, string>): string | null {
  const lit = /^(['"])((?:(?!\1)[^\\\n])*)\1$/.exec(text);
  if (lit) return lit[2]!;
  if (/^[A-Za-z_]\w*$/.test(text)) return consts.get(text) ?? null;
  return null;
}

/** Join prefix parts into one normalized path; '' when every part is empty. */
function combine(...parts: string[]): string {
  const real = parts.filter(Boolean);
  return real.length ? real.reduce((acc, part) => joinPath(acc, part), '') : '';
}

interface PyRouter {
  kind: 'fastapi' | 'flask';
  /** undefined = none given, null = given but not readable. */
  own: string | null | undefined;
  /** Auth dependencies declared on the router/app itself (`APIRouter(dependencies=[Depends(auth)])`). */
  guard: GuardEvidence;
}

interface PyRegistration {
  parent: string;
  child: string;
  kind: 'fastapi' | 'flask';
  /** undefined = no prefix argument, null = given but not readable. */
  prefix: string | null | undefined;
  /** Auth dependencies declared on the registration (`include_router(r, dependencies=[Depends(auth)])`). */
  guard: GuardEvidence;
}

interface PyRouteRec {
  obj: string;
  hit: RouteHit;
}

/** A prefix in front of a router's routes, and whether a Flask blueprint's own `url_prefix` is part of it. */
interface PrefixEntry {
  prefix: string;
  ownBaked: boolean;
  guard: GuardEvidence;
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
    // top-level `NAME = "literal"` assigned exactly once: usable as a prefix.
    const consts = new Map<string, string>();
    // routers/blueprints created in this file, the registrations seen, and the routes recorded with their object.
    const routers = new Map<string, PyRouter>();
    const registrations: PyRegistration[] = [];
    const routeRecs: PyRouteRec[] = [];

    // Normalize CRLF/CR before splitting: FROM_IMPORT_RE anchors on `$`, and JS
    // regex `.` does not match `\r` (a LineTerminator per spec), so a trailing
    // `\r` left on the line from a naive split('\n') silently breaks the match.
    const lines = source.split(/\r\n|\r|\n/);

    const assignCount = new Map<string, number>();
    for (const line of lines) {
      if (line.length > 2000) continue;
      const assigned = TOP_ASSIGN_RE.exec(line);
      if (assigned) assignCount.set(assigned[1]!, (assignCount.get(assigned[1]!) ?? 0) + 1);
      const c = CONST_RE.exec(line);
      if (c) consts.set(c[1]!, c[3]!);
    }
    for (const [name, n] of assignCount) if (n > 1) consts.delete(name);

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
        const callText = extractCall(lines, idx, route.index + route[0].indexOf('('));
        // The decorator's own `dependencies=[Depends(auth)]` (even across lines) and `@login_required` style decorators stacked below it.
        const extra = mergeGuards(authDependencies(callText === null ? undefined : parseCall(callText).kwargs.get('dependencies')), stackedGuards(lines, idx));
        const guardNames = [...new Set([...dependsNames(line), ...extra.names])];
        routeRecs.push({
          obj: route[1]!,
          hit: {
            method: verb === 'route' ? 'ALL' : verb.toUpperCase(),
            path: route[3]!,
            line: idx + 1,
            guarded: /depends|require|auth|login_required/i.test(line) || extra.guarded,
            ...(guardNames.length ? { guardNames } : {}),
          },
        });
      }

      const rdef = ROUTER_DEF_RE.exec(line);
      if (rdef) {
        const kind = rdef[2] === 'Blueprint' ? 'flask' : 'fastapi';
        const inner = extractCall(lines, idx, rdef[0].length - 1);
        let own: string | null | undefined = rdef[2] === 'FastAPI' ? undefined : null;
        let guard = NO_GUARD;
        if (inner !== null) {
          const call = parseCall(inner);
          const raw = call.kwargs.get(kind === 'fastapi' ? 'prefix' : 'url_prefix');
          const stray = kind === 'flask' && call.positional.length > 2;
          own = rdef[2] === 'FastAPI' ? undefined : stray ? null : raw === undefined ? undefined : pyString(raw, consts);
          if (kind === 'fastapi') guard = authDependencies(call.kwargs.get('dependencies'));
        }
        routers.set(rdef[1]!, { kind, own, guard });
      }

      const reg = REGISTER_RE.exec(line);
      if (reg) {
        const kind = reg[2] === 'include_router' ? 'fastapi' : 'flask';
        const inner = extractCall(lines, idx, reg.index + reg[0].length - 1);
        const call = inner === null ? null : parseCall(inner);
        const child = call?.positional[0] ?? call?.kwargs.get(kind === 'fastapi' ? 'router' : 'blueprint') ?? null;
        if (call && child && /^[\w.]+$/.test(child)) {
          const raw = call.kwargs.get(kind === 'fastapi' ? 'prefix' : 'url_prefix');
          const guard = kind === 'fastapi' ? authDependencies(call.kwargs.get('dependencies')) : NO_GUARD;
          registrations.push({ parent: reg[1]!, child, kind, prefix: raw === undefined ? undefined : pyString(raw, consts), guard });
        }
      }

      const def = DEF_RE.exec(line);
      if (def && def[1]) exports.add(def[1]);
    });

    // Prefixes in front of the routes registered on `name`: its own prefix plus the same-file registrations above it. Empty = unreadable, skip.
    const prefixesOf = (name: string, depth = 0): PrefixEntry[] => {
      const router = routers.get(name);
      if (!router || depth > 6) return [{ prefix: '', ownBaked: false, guard: NO_GUARD }];
      const own = router.own;
      const regs = registrations.filter((r) => r.child === name);
      if (regs.length === 0) {
        if (own === null) return [];
        return [{ prefix: own ?? '', ownBaked: router.kind === 'flask' && !!own, guard: router.guard }];
      }
      const out = new Map<string, PrefixEntry>();
      for (const reg of regs) {
        if (reg.prefix === null) continue;
        // FastAPI adds the registration prefix to the router's own; a Flask registration `url_prefix` replaces the blueprint's.
        const replaces = router.kind === 'flask' && reg.prefix !== undefined;
        let mid: string | null;
        if (router.kind === 'flask') mid = replaces ? (reg.prefix ?? '') : (own ?? '');
        else mid = own === null ? null : combine(reg.prefix ?? '', own ?? '');
        if (mid === null || (router.kind === 'flask' && !replaces && own === null)) continue;
        for (const above of prefixesOf(reg.parent, depth + 1)) {
          const prefix = combine(above.prefix, mid);
          const guard = mergeGuards(above.guard, router.guard, reg.guard);
          const prior = out.get(prefix);
          // Reached through several registrations at the same prefix: guarded only if every one of them is.
          out.set(prefix, {
            prefix,
            ownBaked: router.kind === 'flask' && !replaces && !!own,
            guard: prior ? { guarded: prior.guard.guarded && guard.guarded, names: [...new Set([...prior.guard.names, ...guard.names])] } : guard,
          });
        }
      }
      return [...out.values()];
    };

    for (const rec of routeRecs) {
      for (const e of prefixesOf(rec.obj)) {
        const guardNames = [...new Set([...(rec.hit.guardNames ?? []), ...e.guard.names])];
        routes.push({
          ...rec.hit,
          path: e.prefix ? joinPath(e.prefix, rec.hit.path) : rec.hit.path,
          guarded: rec.hit.guarded || e.guard.guarded,
          ...(guardNames.length ? { guardNames } : {}),
          ...(e.ownBaked ? { ownPrefix: true } : {}),
        });
      }
    }

    // Registrations of routers defined elsewhere become cross-file mounts; same-file ones are already folded into the route paths.
    for (const reg of registrations) {
      if (routers.has(reg.child)) continue;
      const targets = PythonAdapter.resolveArg(reg.child, bindings);
      if (targets.length === 0) continue;
      const above = prefixesOf(reg.parent);
      const unreadable = reg.prefix === null || above.length === 0;
      for (const c of targets) {
        if (unreadable) {
          mounts.push({ prefix: '', source: c, unresolved: true });
          continue;
        }
        for (const a of above) {
          const prefix = combine(a.prefix, reg.prefix ?? '');
          const g = mergeGuards(a.guard, reg.guard);
          mounts.push({
            prefix,
            source: c,
            ...(g.guarded ? { guarded: true, guardNames: g.names } : {}),
            ...(reg.kind === 'flask' && reg.prefix !== undefined ? { overridesPrefix: true } : {}),
          });
        }
      }
    }

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
