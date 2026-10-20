/**
 * JS/TS parser using @babel/parser — pure JavaScript, no native build step.
 * Extracts imports, exports, and Express/Koa/Fastify/Hono-style route definitions.
 *
 * Path rule: a route or mount prefix is only reported when it is a string
 * literal, or a template/array/never-reassigned `const` that resolves to
 * strings inside this same file. Anything else (imports, env vars, calls) is
 * skipped, never guessed.
 *
 * Defensive: parsing arbitrary user code can throw; every parse is wrapped and
 * degrades to an empty result rather than crashing the scan.
 */
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import type { Scope } from '@babel/traverse';
import type { Node, CallExpression, ClassDeclaration, ObjectExpression } from '@babel/types';
import type { ParserAdapter, ParseResult, RouteHit, MountHit } from './ParserAdapter';
import { isAuthMiddleware, guardEvidenceNames } from './authMiddleware';
import { joinPath } from '../pathUtil';
import { nestRoutes } from './nest';

// @babel/traverse ships as a CJS module with a `.default` in some setups.
const traverse = (_traverse as unknown as { default?: typeof _traverse }).default ?? _traverse;

type Binding = NonNullable<ReturnType<Scope['getBinding']>>;

// `use` is handled separately as a mount, not an HTTP verb.
const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all']);

// A module path segment like routes/, auth.routes, controllers/ means the binding is a router, not a guard.
const ROUTER_PATH_WORDS = new Set(['route', 'routes', 'router', 'routers', 'controller', 'controllers']);

// Prefix characters that make a `use` prefix a pattern we cannot match segment-wise.
const PATTERN_PREFIX = /[*()?+\\[\]{}]/;

const MAX_RESOLVE_DEPTH = 6;

// Receivers whose `.get('x')` reads a header/cookie/query value and never registers a route.
const NON_ROUTER_RECEIVERS = new Set(['headers', 'cookies', 'searchparams', 'params', 'query', 'formdata', 'localstorage', 'sessionstorage', 'env']);

// NestJS calls that change the final path of every controller.
const NEST_GLOBAL_CALLS = new Map([
  ['setglobalprefix', 'setGlobalPrefix'],
  ['enableversioning', 'enableVersioning'],
]);

// Names that read as a path prefix (`API_PREFIX`, `basePath`, `usersUrl`); only used to tell `use(PREFIX, router)` from `use(middleware, router)`.
const PREFIX_NAME = /^[A-Z][A-Z0-9_]*$/;
const PREFIX_LIKE = /prefix|(path|url|base|root|mount)$/i;

// First `use` argument shapes that might be a path prefix rather than middleware.
const POSSIBLE_PREFIX_TYPES = new Set([
  'Identifier',
  'MemberExpression',
  'TemplateLiteral',
  'BinaryExpression',
  'ArrayExpression',
  'RegExpLiteral',
  'SpreadElement',
  'ConditionalExpression',
  'LogicalExpression',
  'TSAsExpression',
]);

/** True if a node is `require('some-string')`. */
function requireSource(node: Node | null | undefined): string | null {
  if (
    node &&
    node.type === 'CallExpression' &&
    node.callee.type === 'Identifier' &&
    node.callee.name === 'require' &&
    node.arguments[0]?.type === 'StringLiteral'
  ) {
    return node.arguments[0].value;
  }
  return null;
}

/** `require('x')` or `import('x')` (Fastify accepts a dynamic import as a plugin). */
function moduleSource(node: Node | null | undefined): string | null {
  const req = requireSource(node);
  if (req) return req;
  if (node && node.type === 'CallExpression' && node.callee.type === 'Import' && node.arguments[0]?.type === 'StringLiteral') {
    return node.arguments[0].value;
  }
  return null;
}

/** Stable name for the object a route/use is registered on (`app`, `this.router`), or null. */
function objectKey(node: Node): string | null {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier') {
    const base = objectKey(node.object);
    return base ? `${base}.${node.property.name}` : null;
  }
  return null;
}

function segments(p: string): string[] {
  return p.split('/').filter(Boolean);
}

/** Segment-aware prefix test: `/admin` covers `/admin/stats` but not `/administrator`. */
function covers(prefix: string[], target: string[]): boolean {
  return prefix.length <= target.length && prefix.every((s, i) => s === target[i]);
}

function uniq(names: string[]): string[] {
  return [...new Set(names)];
}

function withNames<T extends object>(obj: T, names: string[]): T & { guardNames?: string[] } {
  const u = uniq(names);
  return u.length ? { ...obj, guardNames: u } : obj;
}

function isRouterSpecifier(spec: string): boolean {
  return spec
    .toLowerCase()
    .split(/[/.\\]/)
    .some((s) => ROUTER_PATH_WORDS.has(s));
}

function unwrap(node: Node): Node {
  let n = node;
  while (
    n.type === 'TSAsExpression' ||
    n.type === 'TSSatisfiesExpression' ||
    n.type === 'TSNonNullExpression' ||
    n.type === 'TSTypeAssertion' ||
    n.type === 'ParenthesizedExpression'
  ) {
    n = n.expression;
  }
  return n;
}

/** The string a node evaluates to from literals, template literals and never-reassigned same-file constants; null for anything else. */
function resolveStr(node: Node | null | undefined, scope: Scope, depth = 0): string | null {
  if (!node || depth > MAX_RESOLVE_DEPTH) return null;
  const n = unwrap(node);
  if (n.type === 'StringLiteral') return n.value;
  if (n.type === 'TemplateLiteral') {
    let out = '';
    for (let i = 0; i < n.quasis.length; i++) {
      const cooked = n.quasis[i]!.value.cooked;
      if (cooked === null || cooked === undefined) return null;
      out += cooked;
      const expr = n.expressions[i];
      if (expr) {
        const v = resolveStr(expr as Node, scope, depth + 1);
        if (v === null) return null;
        out += v;
      }
    }
    return out;
  }
  if (n.type === 'Identifier') {
    const b = scope.getBinding(n.name);
    const decl = b?.path.node;
    if (b && b.constant && decl?.type === 'VariableDeclarator' && decl.id.type === 'Identifier' && decl.init) {
      return resolveStr(decl.init, b.scope, depth + 1);
    }
  }
  return null;
}

/** `request.headers.get(..)`, `cookies().get(..)`, `searchParams.get(..)`: a value lookup, not a route registration. */
function isNonRouterReceiver(obj: Node): boolean {
  const o = unwrap(obj);
  if (o.type === 'CallExpression') {
    const name = calleeName(o.callee);
    return name !== null && NON_ROUTER_RECEIVERS.has(name.toLowerCase());
  }
  const key = objectKey(o);
  return key !== null && NON_ROUTER_RECEIVERS.has(key.split('.').pop()!.toLowerCase());
}

/** Route path argument: a string literal, or a constant/template/array of them (non-literal forms must look like a path). */
function resolvePaths(node: Node | null | undefined, scope: Scope): string[] | null {
  if (!node) return null;
  const n = unwrap(node);
  // Express settings getters (`app.get('env')`) and header lookups pass a bare word: a route path starts with '/' (or is a '*' wildcard).
  if (n.type === 'StringLiteral') return n.value.startsWith('/') || n.value.startsWith('*') ? [n.value] : null;
  if (n.type === 'ArrayExpression') {
    const out: string[] = [];
    for (const el of n.elements) {
      if (!el || el.type === 'SpreadElement') continue;
      const v = resolveStr(el, scope);
      if (v !== null && v.startsWith('/')) out.push(v);
    }
    return out.length ? out : null;
  }
  const v = resolveStr(n, scope);
  return v !== null && v.startsWith('/') ? [v] : null;
}

/** Strings in an array whose elements all resolve (a `use` prefix list), or null. */
function resolveStrArray(node: Node, scope: Scope): string[] | null {
  const n = unwrap(node);
  if (n.type !== 'ArrayExpression' || n.elements.length === 0) return null;
  const out: string[] = [];
  for (const el of n.elements) {
    if (!el || el.type === 'SpreadElement') return null;
    const v = resolveStr(el, scope);
    if (v === null) return null;
    out.push(v);
  }
  return out;
}

/** Object literal behind an options argument (inline, or a same-file const), or null. */
function objectLiteral(node: Node | null | undefined, scope: Scope, depth = 0): ObjectExpression | null {
  if (!node || depth > MAX_RESOLVE_DEPTH) return null;
  const n = unwrap(node);
  if (n.type === 'ObjectExpression') return n;
  if (n.type === 'Identifier') {
    const b = scope.getBinding(n.name);
    const decl = b?.path.node;
    if (b && b.constant && decl?.type === 'VariableDeclarator' && decl.id.type === 'Identifier' && decl.init) {
      return objectLiteral(decl.init, b.scope, depth + 1);
    }
  }
  return null;
}

/** Value of `key` in an object literal: undefined if absent, null if the literal has spreads/computed keys/methods we cannot read. */
function propValue(obj: ObjectExpression, key: string): Node | undefined | null {
  let found: Node | undefined;
  for (const prop of obj.properties) {
    if (prop.type === 'SpreadElement') return null;
    if (prop.computed) return null;
    const name = prop.key.type === 'Identifier' ? prop.key.name : prop.key.type === 'StringLiteral' ? prop.key.value : null;
    if (name !== key) continue;
    if (prop.type !== 'ObjectProperty') return null;
    found = prop.value;
  }
  return found;
}

function calleeName(callee: Node): string | null {
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') return callee.property.name;
  return null;
}

/** Join prefix parts into one normalized path; '' when every part is empty. */
function combine(...parts: string[]): string {
  const real = parts.filter(Boolean);
  return real.length ? real.reduce((acc, part) => joinPath(acc, part), '') : '';
}

/** Prefix an object carries from the call that created it: `new Router({ prefix })`, Hono `.basePath('/x')`. '' = none, null = not resolvable. */
function creationPrefix(init: Node, scope: Scope): string | null {
  const n = unwrap(init);
  if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && calleeName(n.callee) === 'basePath' && n.arguments[0]) {
    const base = creationPrefix(n.callee.object, scope);
    const own = resolveStr(n.arguments[0] as Node, scope);
    return base === null || own === null ? null : combine(base, own);
  }
  if ((n.type === 'NewExpression' || n.type === 'CallExpression') && /Router$/.test(calleeName(n.callee) ?? '')) {
    const opts = n.arguments[0];
    if (!opts) return '';
    const obj = objectLiteral(opts as Node, scope);
    if (!obj) return null;
    const v = propValue(obj, 'prefix');
    if (v === undefined) return '';
    return v === null ? null : resolveStr(v, scope);
  }
  return '';
}

/** Fastify `register(plugin, opts)`: the prefix list the plugin's routes get; null when opts is present but its prefix is not readable. */
function registerPrefix(opts: Node | undefined, scope: Scope): string[] | null {
  if (!opts) return [''];
  const obj = objectLiteral(opts, scope);
  if (!obj) return null;
  if (propValue(obj, 'routes') !== undefined) return null;
  const v = propValue(obj, 'prefix');
  if (v === undefined) return [''];
  const s = v === null ? null : resolveStr(v, scope);
  return s === null ? null : [s];
}

/** Does the first `use` argument read as a path prefix we cannot resolve (so the mount is skipped, not guessed)? */
function looksLikeUnresolvedPrefix(first: Node, argCount: number, scope: Scope): boolean {
  const n = unwrap(first);
  if (n.type === 'TemplateLiteral' || n.type === 'RegExpLiteral') return true;
  if (n.type === 'BinaryExpression') return n.operator === '+';
  if (argCount < 2) return false;
  if (n.type === 'ArrayExpression') return n.elements.some((e) => e && (e.type === 'StringLiteral' || e.type === 'TemplateLiteral'));
  if (n.type === 'Identifier') {
    const decl = scope.getBinding(n.name)?.path.node;
    if (decl?.type === 'VariableDeclarator' && decl.init) {
      const initType = unwrap(decl.init).type;
      const stringish = ['StringLiteral', 'TemplateLiteral', 'Identifier', 'MemberExpression', 'BinaryExpression', 'ConditionalExpression', 'LogicalExpression'];
      if (!stringish.includes(initType)) return false;
    }
    return PREFIX_NAME.test(n.name) || PREFIX_LIKE.test(n.name);
  }
  if (n.type === 'MemberExpression') {
    if (n.computed || n.property.type !== 'Identifier') return false;
    return PREFIX_NAME.test(n.property.name) || PREFIX_LIKE.test(n.property.name) || objectKey(n.object) === 'process.env';
  }
  if (n.type === 'ConditionalExpression' || n.type === 'LogicalExpression') {
    const leaves = n.type === 'ConditionalExpression' ? [n.consequent, n.alternate] : [n.left, n.right];
    return leaves.some((l) => {
      const u = unwrap(l);
      return u.type === 'StringLiteral' && u.value.startsWith('/');
    });
  }
  return false;
}

/** `app.route('/x').get(h).post(h)`: the `.route('/x')` call at the base of a verb chain, plus the arguments of every `.all(...)` step below the verb. */
function routeChainBase(node: Node): { base: CallExpression; allArgs: Node[] } | null {
  let cur = node;
  const allArgs: Node[] = [];
  for (let i = 0; i < 20; i++) {
    if (cur.type !== 'CallExpression' || cur.callee.type !== 'MemberExpression') return null;
    const name = calleeName(cur.callee)?.toLowerCase();
    if (!name) return null;
    if (name === 'route') return cur.arguments.length === 1 ? { base: cur, allArgs } : null;
    if (!HTTP_METHODS.has(name)) return null;
    if (name === 'all') allArgs.push(...(cur.arguments as Node[]));
    cur = cur.callee.object;
  }
  return null;
}

/** A router/app mounted inside this same file (`app.use('/api', router)`, `app.route('/x', sub)`, `register(plugin, { prefix })`). */
interface LocalMount {
  obj: Node;
  scope: Scope;
  /** null = the prefix is not resolvable. */
  prefixes: string[] | null;
}

interface FileMount extends LocalMount {
  source: string;
  guarded: boolean;
  guardNames: string[];
}

interface RouteRec {
  obj: Node;
  scope: Scope;
  hit: RouteHit;
}

export class BabelAdapter implements ParserAdapter {
  readonly extensions = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

  parse(relPath: string, source: string): ParseResult {
    const imports = new Set<string>();
    const exports = new Set<string>();
    const routes: RouteHit[] = [];
    const mounts: MountHit[] = [];
    // local identifier -> module specifier it was imported/required from.
    const bindings = new Map<string, string>();
    // mounts of imported/required routers; resolved to prefixes after traversal.
    const fileMounts: FileMount[] = [];
    // routes recorded with the object they were registered on; prefixed after traversal.
    const routeRecs: RouteRec[] = [];
    // same-file mounts, keyed by the mounted router's declaring identifier (or, for Fastify plugins, the plugin function node).
    const localMounts = new Map<Node, LocalMount[]>();
    // declaring identifiers of routers that had `.prefix(...)` called on them (Koa): their final prefix is not tracked.
    const prefixCalled = new Set<Node>();
    // object key (`app`, `router`) -> path-prefix segments (and names) of auth middleware applied via `use`, in source order.
    const scopeGuards = new Map<string, { scope: string[]; names: string[] }[]>();
    // classes seen (NestJS controllers are read from these after the traversal, once every import is known) and Nest calls that change every controller path.
    const classes: { node: ClassDeclaration; scope: Scope }[] = [];
    const nestGlobal = new Set<string>();
    const scopedNames = (key: string | null, target: string[]): string[] =>
      key === null ? [] : (scopeGuards.get(key) ?? []).filter((g) => covers(g.scope, target)).flatMap((g) => g.names);

    // A recognised auth middleware, unless it is an identifier imported from a routes/controllers module.
    const isGuard = (a: Node): boolean => {
      if (!isAuthMiddleware(a)) return false;
      if (a.type !== 'Identifier') return true;
      const spec = bindings.get(a.name);
      return !(spec && isRouterSpecifier(spec));
    };

    const addLocalMount = (key: Node, m: LocalMount): void => {
      const list = localMounts.get(key) ?? [];
      list.push(m);
      localMounts.set(key, list);
    };

    /**
     * Record that `target` is mounted on `obj` at `prefixes`. An imported router
     * becomes a file mount; a router/plugin defined in this file is tracked locally.
     * `allowFunctions` is only true for Fastify `register`: elsewhere a function
     * argument is a handler, not a plugin.
     */
    const recordMount = (
      obj: Node,
      scope: Scope,
      prefixes: string[] | null,
      target: Node,
      guarded: boolean,
      guardNames: string[],
      allowFunctions: boolean,
    ): void => {
      const src = moduleSource(target);
      if (src) {
        fileMounts.push({ obj, scope, prefixes, source: src, guarded, guardNames });
        return;
      }
      if (allowFunctions && (target.type === 'FunctionExpression' || target.type === 'ArrowFunctionExpression')) {
        addLocalMount(target, { obj, scope, prefixes });
        return;
      }
      if (target.type !== 'Identifier') return;
      const imported = bindings.get(target.name);
      if (imported) {
        fileMounts.push({ obj, scope, prefixes, source: imported, guarded, guardNames });
        return;
      }
      const b = scope.getBinding(target.name);
      if (!b) return;
      const decl = b.path.node;
      if (decl.type === 'FunctionDeclaration') {
        if (allowFunctions) addLocalMount(decl, { obj, scope, prefixes });
      } else if (decl.type === 'VariableDeclarator' && decl.init && isFunctionLike(decl.init)) {
        if (allowFunctions) addLocalMount(unwrap(decl.init), { obj, scope, prefixes });
      } else if (decl.type === 'VariableDeclarator') {
        addLocalMount(b.identifier, { obj, scope, prefixes });
      }
    };

    const isFunctionLike = (n: Node): boolean => {
      const u = unwrap(n);
      return u.type === 'FunctionExpression' || u.type === 'ArrowFunctionExpression';
    };

    const ownPrefix = (b: Binding): string | null => {
      if (prefixCalled.has(b.identifier)) return null;
      const decl = b.path.node;
      if (decl.type !== 'VariableDeclarator' || !decl.init) return '';
      return creationPrefix(decl.init, b.scope);
    };

    /** Every full prefix the routes registered on `obj` live under: its own prefix plus the same-file mounts above it. Empty = unknowable, skip. */
    const ownerPrefixes = (obj: Node | null, scope: Scope, depth = 0): string[] => {
      if (!obj || obj.type !== 'Identifier' || depth > MAX_RESOLVE_DEPTH) return [''];
      const b = scope.getBinding(obj.name);
      if (!b) return [''];
      const own = ownPrefix(b);
      if (own === null) return [];
      const regs = [...(localMounts.get(b.identifier) ?? [])];
      const fn = b.scope.block;
      if (b.kind === 'param' && 'params' in fn && fn.params[0] === b.identifier) regs.push(...(localMounts.get(fn) ?? []));
      if (regs.length === 0) return [own];
      const out = new Set<string>();
      for (const r of regs) {
        if (r.prefixes === null) continue;
        for (const above of ownerPrefixes(r.obj, r.scope, depth + 1)) {
          for (const rp of r.prefixes) out.add(combine(above, rp, own));
        }
      }
      return [...out];
    };

    let ast;
    try {
      ast = parse(source, {
        sourceType: 'unambiguous',
        errorRecovery: true,
        plugins: [
          'typescript',
          'jsx',
          'decorators-legacy',
          'classProperties',
          'topLevelAwait',
          'importAssertions',
        ],
      });
    } catch {
      return { imports: [], exports: [], routes: [], mounts: [] };
    }

    try {
      traverse(ast, {
        ImportDeclaration(p) {
          const src = p.node.source.value;
          imports.add(src);
          // Record default/named/namespace bindings so mounts can resolve them.
          for (const spec of p.node.specifiers) {
            bindings.set(spec.local.name, src);
          }
        },
        VariableDeclarator(p) {
          // const authRoutes = require('./routes/auth')
          const src = requireSource(p.node.init);
          if (src && p.node.id.type === 'Identifier') bindings.set(p.node.id.name, src);
        },
        CallExpression(p) {
          const callee = p.node.callee;
          // require('x')
          if (callee.type === 'Identifier' && callee.name === 'require') {
            const arg = p.node.arguments[0];
            if (arg && arg.type === 'StringLiteral') imports.add(arg.value);
            return;
          }
          if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier') return;
          const method = callee.property.name.toLowerCase();
          const args = p.node.arguments;
          const key = objectKey(callee.object);
          const scope = p.scope;

          // NestJS: app.setGlobalPrefix(..), app.enableVersioning(..), RouterModule.register(..) rewrite the path of every controller.
          const nestCall = NEST_GLOBAL_CALLS.get(method);
          if (nestCall) nestGlobal.add(nestCall);
          else if (method === 'register' && key === 'RouterModule') nestGlobal.add('RouterModule');

          // koa-router `router.prefix('/x')` rewrites the prefix of every route; we do not track it.
          if (method === 'prefix' && callee.object.type === 'Identifier') {
            const b = scope.getBinding(callee.object.name);
            if (b) prefixCalled.add(b.identifier);
            return;
          }

          // Fastify: fastify.register(plugin, { prefix: '/api' })
          if (method === 'register' && args[0]) {
            const prefixes = registerPrefix(args[1] as Node | undefined, scope);
            recordMount(callee.object, scope, prefixes, args[0], false, [], true);
            return;
          }

          // Hono: app.route('/admin', adminApp)  (Express' one-argument app.route('/x') is a chain base, handled with its verbs)
          if (method === 'route' && args.length >= 2 && args[1]) {
            const prefix = resolveStr(args[0] as Node, scope);
            recordMount(callee.object, scope, prefix === null ? null : [prefix], args[1], false, [], false);
            return;
          }

          // app.use('/api/auth', authRoutes) — a sub-router mount; app.use(auth) — a guard.
          if (method === 'use') {
            let prefix = '';
            let prefixes: string[] | null = [''];
            let i = 0;
            let scopeKnown = true;
            const first = args[0];
            if (first?.type === 'StringLiteral') {
              prefix = first.value;
              prefixes = [prefix];
              i = 1;
              if (PATTERN_PREFIX.test(prefix)) scopeKnown = false;
            } else if (first && !isGuard(first) && POSSIBLE_PREFIX_TYPES.has(first.type)) {
              scopeKnown = false; // could be a dynamic prefix: do not invent a guard
              const constant = resolveStr(first, scope);
              const list = constant === null ? resolveStrArray(first, scope) : null;
              if (constant !== null) {
                // app.use(API_PREFIX, router) with a same-file constant
                prefix = constant;
                prefixes = [constant];
                i = 1;
                scopeKnown = !PATTERN_PREFIX.test(constant);
              } else if (list) {
                prefixes = list;
                i = 1;
              } else if (looksLikeUnresolvedPrefix(first, args.length, scope)) {
                prefixes = null; // a prefix we cannot read: mounted routes are skipped
                i = 1;
              }
            }
            // Mounts are guarded by an auth middleware earlier in this call or an earlier `use` covering the prefix.
            let guardSeen = false;
            const callGuardNames: string[] = [];
            const mountGuarded = () =>
              guardSeen || (key !== null && (scopeGuards.get(key) ?? []).some((g) => covers(g.scope, segments(prefix))));
            const mountNames = () => [...callGuardNames, ...scopedNames(key, segments(prefix))];
            for (; i < args.length; i++) {
              const a = args[i]!;
              if (isGuard(a)) {
                guardSeen = true;
                const names = guardEvidenceNames(a);
                callGuardNames.push(...names);
                if (scopeKnown && key) {
                  const list = scopeGuards.get(key) ?? [];
                  list.push({ scope: segments(prefix), names });
                  scopeGuards.set(key, list);
                }
                continue;
              }
              recordMount(callee.object, scope, prefixes, a, mountGuarded(), mountNames(), false);
            }
            return;
          }

          // app.get('/path', ...), router.post('/x', auth, handler), app.route('/x').get(h).post(h)
          if (!HTTP_METHODS.has(method)) return;
          const chain = routeChainBase(callee.object);
          let paths: string[] | null;
          let owner: Node;
          let routeGuards: Node[];
          if (chain) {
            const baseCallee = chain.base.callee as Extract<Node, { type: 'MemberExpression' }>;
            owner = baseCallee.object;
            paths = resolvePaths(chain.base.arguments[0] as Node, scope);
            // `.all(requireAuth)` below this verb guards it too; a verb whose arguments are all guards is a guard step, not a route.
            if (method === 'all' && args.length > 0 && args.every((a) => isGuard(a))) return;
            routeGuards = [...chain.allArgs, ...args.slice(0, -1)].filter((a) => isGuard(a));
          } else {
            const first = args[0];
            // A registration has a handler after the path, and its receiver is a router/app, not headers/cookies/params.
            if (!first || args.length < 2 || isNonRouterReceiver(callee.object)) return;
            owner = callee.object;
            paths = resolvePaths(first, scope);
            // Middleware sits between the path and the final handler; the handler itself is never a guard.
            routeGuards = args.slice(1, -1).filter((a) => isGuard(a));
          }
          if (!paths) return;
          const routeKey = chain ? objectKey(owner) : key;
          for (const routePath of paths) {
            const target = segments(routePath);
            const scoped = routeKey !== null && (scopeGuards.get(routeKey) ?? []).some((g) => covers(g.scope, target));
            const names = [...routeGuards.flatMap(guardEvidenceNames), ...scopedNames(routeKey, target)];
            routeRecs.push({
              obj: owner,
              scope,
              hit: withNames(
                {
                  method: method === 'all' ? 'ALL' : method.toUpperCase(),
                  path: routePath,
                  line: p.node.loc?.start.line,
                  guarded: routeGuards.length > 0 || scoped,
                },
                names,
              ),
            });
          }
        },
        ClassDeclaration(p) {
          if (p.node.decorators?.length) classes.push({ node: p.node, scope: p.scope });
        },
        ExportNamedDeclaration(p) {
          const decl = p.node.declaration;
          if (decl && 'declarations' in decl && Array.isArray(decl.declarations)) {
            for (const d of decl.declarations) {
              if (d.id.type === 'Identifier') exports.add(d.id.name);
            }
          } else if (decl && 'id' in decl && decl.id && decl.id.type === 'Identifier') {
            exports.add(decl.id.name);
          }
          for (const spec of p.node.specifiers) {
            if (spec.exported.type === 'Identifier') exports.add(spec.exported.name);
          }
        },
        AssignmentExpression(p) {
          // module.exports.foo = ... / exports.foo = ...
          const left = p.node.left;
          if (
            left.type === 'MemberExpression' &&
            left.property.type === 'Identifier' &&
            left.object.type === 'MemberExpression' &&
            left.object.property.type === 'Identifier' &&
            left.object.property.name === 'exports'
          ) {
            exports.add(left.property.name);
          }
        },
      });
    } catch {
      // Traversal can still throw on exotic nodes — keep whatever we gathered.
    }

    // NestJS controllers (decorators imported from @nestjs/common only).
    try {
      routes.push(...nestRoutes(classes, resolveStr, (name) => bindings.get(name) === '@nestjs/common'));
    } catch {
      // A decorator shape we do not understand: keep the other routes.
    }

    // Routes live under the prefixes of the router/plugin they were registered on; none resolvable = skipped.
    for (const r of routeRecs) {
      for (const above of ownerPrefixes(r.obj, r.scope)) {
        routes.push(above ? { ...r.hit, path: joinPath(above, r.hit.path) } : r.hit);
      }
    }

    // Imported routers: mounts keep the prefix of whatever they were registered on; an unreadable prefix marks the mount unresolved.
    for (const m of fileMounts) {
      const flags = { ...(m.guarded ? { guarded: true } : {}) };
      const above = ownerPrefixes(m.obj, m.scope);
      if (m.prefixes === null || above.length === 0) {
        mounts.push(withNames({ prefix: '', source: m.source, unresolved: true, ...flags }, m.guardNames));
        continue;
      }
      for (const a of above) {
        for (const prefix of m.prefixes) {
          mounts.push(withNames({ prefix: a ? combine(a, prefix) : prefix, source: m.source, ...flags }, m.guardNames));
        }
      }
    }

    return {
      imports: [...imports],
      exports: [...exports],
      routes,
      mounts,
      ...(nestGlobal.size ? { nestGlobalConfig: [...nestGlobal] } : {}),
    };
  }
}
