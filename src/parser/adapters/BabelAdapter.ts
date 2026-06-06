/**
 * JS/TS parser using @babel/parser — pure JavaScript, no native build step.
 * Extracts imports, exports, and Express/Koa/Fastify-style route definitions.
 *
 * Defensive: parsing arbitrary user code can throw; every parse is wrapped and
 * degrades to an empty result rather than crashing the scan.
 */
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import type { ParserAdapter, ParseResult, RouteHit, MountHit } from './ParserAdapter';

// @babel/traverse ships as a CJS module with a `.default` in some setups.
const traverse = (_traverse as unknown as { default?: typeof _traverse }).default ?? _traverse;

// `use` is handled separately as a mount, not an HTTP verb.
const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all']);

/** True if a node is `require('some-string')`. */
function requireSource(node: import('@babel/types').Node | null | undefined): string | null {
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

export class BabelAdapter implements ParserAdapter {
  readonly extensions = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

  parse(relPath: string, source: string): ParseResult {
    const imports = new Set<string>();
    const exports = new Set<string>();
    const routes: RouteHit[] = [];
    const mounts: MountHit[] = [];
    // local identifier -> module specifier it was imported/required from.
    const bindings = new Map<string, string>();
    // mounts whose router identifier we resolve to a specifier after traversal.
    const pendingMounts: { prefix: string; ident: string }[] = [];

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

          // app.use('/api/auth', authRoutes) — a sub-router mount.
          if (method === 'use') {
            let prefix = '';
            let i = 0;
            if (args[0]?.type === 'StringLiteral') {
              prefix = args[0].value;
              i = 1;
            }
            for (; i < args.length; i++) {
              const a = args[i]!;
              if (a.type === 'Identifier') pendingMounts.push({ prefix, ident: a.name });
              else {
                const src = requireSource(a); // app.use('/x', require('./y'))
                if (src) mounts.push({ prefix, source: src });
              }
            }
            return;
          }

          // app.get('/path', ...), router.post('/x', auth, handler)
          if (!HTTP_METHODS.has(method)) return;
          const first = args[0];
          if (!first || first.type !== 'StringLiteral') return;
          routes.push({
            method: method === 'all' ? 'ALL' : method.toUpperCase(),
            path: first.value,
            line: p.node.loc?.start.line,
            // >2 args means middleware sits between the path and the final handler.
            guarded: args.length > 2,
          });
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

    // Resolve mounted router identifiers to the module they were imported from.
    for (const m of pendingMounts) {
      const source = bindings.get(m.ident);
      if (source) mounts.push({ prefix: m.prefix, source });
    }

    return {
      imports: [...imports],
      exports: [...exports],
      routes,
      mounts,
    };
  }
}
