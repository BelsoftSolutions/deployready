/**
 * JS/TS parser using @babel/parser — pure JavaScript, no native build step.
 * Extracts imports, exports, and Express/Koa/Fastify-style route definitions.
 *
 * Defensive: parsing arbitrary user code can throw; every parse is wrapped and
 * degrades to an empty result rather than crashing the scan.
 */
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import type { ParserAdapter, ParseResult, RouteHit } from './ParserAdapter';

// @babel/traverse ships as a CJS module with a `.default` in some setups.
const traverse = (_traverse as unknown as { default?: typeof _traverse }).default ?? _traverse;

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all', 'use']);

export class BabelAdapter implements ParserAdapter {
  readonly extensions = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

  parse(relPath: string, source: string): ParseResult {
    const imports = new Set<string>();
    const exports = new Set<string>();
    const routes: RouteHit[] = [];

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
      return { imports: [], exports: [], routes: [] };
    }

    try {
      traverse(ast, {
        ImportDeclaration(p) {
          imports.add(p.node.source.value);
        },
        CallExpression(p) {
          const callee = p.node.callee;
          // require('x')
          if (callee.type === 'Identifier' && callee.name === 'require') {
            const arg = p.node.arguments[0];
            if (arg && arg.type === 'StringLiteral') imports.add(arg.value);
            return;
          }
          // app.get('/path', ...), router.post('/x', auth, handler)
          if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
            const method = callee.property.name.toLowerCase();
            if (!HTTP_METHODS.has(method)) return;
            const args = p.node.arguments;
            const first = args[0];
            if (!first || first.type !== 'StringLiteral') return;
            const routePath = first.value;
            if (method === 'use' && !routePath.startsWith('/')) return;
            routes.push({
              method: method === 'all' || method === 'use' ? 'ALL' : method.toUpperCase(),
              path: routePath,
              line: p.node.loc?.start.line,
              // >2 args means middleware sits between the path and the final handler.
              guarded: args.length > 2,
            });
          }
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

    return {
      imports: [...imports],
      exports: [...exports],
      routes,
    };
  }
}
