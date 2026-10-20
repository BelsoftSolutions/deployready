/**
 * NestJS controllers: `@Controller('prefix')` + `@Get/@Post/...('sub')` become
 * routes; `@UseGuards(...)` and role/permission decorators are guard evidence.
 *
 * Path rule (same as the rest of the parser): a prefix or sub-path is used only
 * when it is a string literal or a same-file constant. Anything else skips that
 * route. A decorator counts only when it was imported from `@nestjs/common`.
 * Global prefix, RouterModule mounting and versioning are not resolved here;
 * BabelAdapter flags them so CodeParser drops the Nest routes instead of
 * guessing the final path.
 */
import type { Scope } from '@babel/traverse';
import type { ClassDeclaration, ClassMethod, Decorator, Node } from '@babel/types';
import type { RouteHit } from './ParserAdapter';
import { isNestGuardName, isNestAccessDecorator, isOpenAccessName } from './authMiddleware';
import { joinPath } from '../pathUtil';

export type StrResolver = (node: Node, scope: Scope) => string | null;

const NEST_VERBS = new Map<string, string>(Object.entries({
  Get: 'GET',
  Post: 'POST',
  Put: 'PUT',
  Patch: 'PATCH',
  Delete: 'DELETE',
  Options: 'OPTIONS',
  Head: 'HEAD',
  All: 'ALL',
}));

// Decorators that never express access control, whatever their name looks like.
const PLAIN_DECORATORS = new Set(['Controller', 'UseGuards', 'Injectable', 'Version', 'Header', 'HttpCode', 'Redirect', 'Render', 'UseInterceptors', 'UsePipes', 'UseFilters', 'SetMetadata', 'ApiTags', 'ApiOperation', 'ApiResponse', 'ApiBearerAuth']);

interface DecoratorCall {
  name: string;
  args: Node[];
}

function decoratorCall(d: Decorator): DecoratorCall | null {
  const e = d.expression;
  if (e.type === 'CallExpression' && e.callee.type === 'Identifier') return { name: e.callee.name, args: e.arguments as Node[] };
  if (e.type === 'Identifier') return { name: e.name, args: [] };
  return null;
}

/** Name an expression refers to: `AuthGuard`, `AuthGuard('jwt')`, `guards.AuthGuard`. */
function exprName(node: Node): string | null {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'CallExpression') return exprName(node.callee);
  if (node.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier') return node.property.name;
  return null;
}

/** String literals and member names (`Role.Admin` -> `Admin`) among call arguments: evidence for what a role decorator demands. */
function argWords(args: Node[]): string[] {
  const out: string[] = [];
  const visit = (n: Node): void => {
    if (n.type === 'StringLiteral') {
      if (n.value) out.push(n.value);
    } else if (n.type === 'MemberExpression' && !n.computed && n.property.type === 'Identifier') {
      out.push(n.property.name);
    } else if (n.type === 'ArrayExpression') {
      for (const el of n.elements) if (el && el.type !== 'SpreadElement') visit(el);
    }
  };
  args.forEach(visit);
  return out;
}

interface Evidence {
  names: string[];
  open: boolean;
}

/** Guard evidence carried by a list of decorators (a controller class or one handler). */
function evidenceOf(decorators: Decorator[] | null | undefined, has: (name: string) => boolean): Evidence {
  const names: string[] = [];
  let open = false;
  for (const d of decorators ?? []) {
    const call = decoratorCall(d);
    if (!call || call.name !== 'UseGuards' || !has('UseGuards')) continue;
    for (const arg of call.args) {
      const guard = exprName(arg);
      if (guard && isNestGuardName(guard)) names.push(guard, ...argWords(arg.type === 'CallExpression' ? (arg.arguments as Node[]) : []));
    }
  }
  // Role/permission decorators are project-defined, so they are not limited to `@nestjs/common` imports.
  for (const d of decorators ?? []) {
    const call = decoratorCall(d);
    if (!call || PLAIN_DECORATORS.has(call.name) || NEST_VERBS.has(call.name)) continue;
    if (isOpenAccessName(call.name)) open = true;
    else if (isNestAccessDecorator(call.name)) names.push(call.name, ...argWords(call.args));
  }
  return { names: [...new Set(names)], open };
}

/** Paths a decorator argument yields: none given -> [''], literal/constant -> [it], array of them -> all; null = not readable, skip. */
function pathsOf(args: Node[], scope: Scope, resolve: StrResolver, controller: boolean): string[] | null {
  const first = args[0];
  if (!first) return [''];
  let target: Node | undefined = first;
  if (controller && first.type === 'ObjectExpression') {
    target = undefined;
    for (const prop of first.properties) {
      if (prop.type !== 'ObjectProperty' || prop.computed) return null;
      const key = prop.key.type === 'Identifier' ? prop.key.name : prop.key.type === 'StringLiteral' ? prop.key.value : null;
      if (key === 'path') target = prop.value;
      else if (key === 'version' || key === 'host') return null; // changes the URL (or the Host it answers on): not resolved
    }
    if (!target) return [''];
  }
  if (target.type === 'ArrayExpression') {
    const out: string[] = [];
    for (const el of target.elements) {
      if (!el || el.type === 'SpreadElement') return null;
      const v = resolve(el, scope);
      if (v === null) return null;
      out.push(v);
    }
    return out.length ? out : null;
  }
  const v = resolve(target, scope);
  return v === null ? null : [v];
}

export function nestRoutes(classes: { node: ClassDeclaration; scope: Scope }[], resolve: StrResolver, importedFromNest: (name: string) => boolean): RouteHit[] {
  const hits: RouteHit[] = [];
  for (const { node, scope } of classes) {
    const controller = (node.decorators ?? []).map(decoratorCall).find((c) => c?.name === 'Controller');
    if (!controller || !importedFromNest('Controller')) continue;
    const prefixes = pathsOf(controller.args, scope, resolve, true);
    if (!prefixes) continue;
    const classEv = evidenceOf(node.decorators, importedFromNest);

    for (const member of node.body.body) {
      if (member.type !== 'ClassMethod') continue;
      const m: ClassMethod = member;
      const decorators = m.decorators ?? [];
      if (decorators.some((d) => decoratorCall(d)?.name === 'Version')) continue;
      const methodEv = evidenceOf(m.decorators, importedFromNest);
      for (const d of decorators) {
        const call = decoratorCall(d);
        const verb = call ? NEST_VERBS.get(call.name) : undefined;
        if (!call || !verb || !importedFromNest(call.name)) continue;
        const subs = pathsOf(call.args, scope, resolve, false);
        if (!subs) continue;
        const names = [...new Set([...classEv.names, ...methodEv.names])];
        const open = classEv.open || methodEv.open;
        for (const prefix of prefixes) {
          for (const sub of subs) {
            hits.push({
              method: verb,
              path: joinPath(prefix, sub),
              line: d.loc?.start.line ?? m.loc?.start.line,
              guarded: !open && names.length > 0,
              ...(!open && names.length ? { guardNames: names } : {}),
              nest: true,
            });
          }
        }
      }
    }
  }
  return hits;
}
