/**
 * Recognises auth middleware by camelCase/snake_case word tokens, never by
 * substring, so `requireAuth` / `ensureLoggedIn` match while `author`,
 * `authorName` and `oauthCallback` do not.
 */
import type { Node } from '@babel/types';

const GUARD_WORDS = new Set([
  'auth',
  'authn',
  'authz',
  'authenticate',
  'authenticated',
  'authentication',
  'authorize',
  'authorise',
  'authorized',
  'authorised',
  'authorization',
  'authorisation',
  'jwt',
  'expressjwt',
  'logged',
  'protect',
  'protected',
  'passport',
]);

const CHECK_VERBS = ['check', 'require', 'ensure', 'verify', 'validate'];

const STAFF_VERBS = ['is', 'require', 'ensure', 'check', 'only'];

// noun -> verbs that turn it into a guard (`session` alone is not one).
const NOUN_VERBS: Record<string, string[]> = {
  session: CHECK_VERBS,
  token: CHECK_VERBS,
  user: ['require', 'ensure'],
  login: ['require', 'ensure', 'check', 'verify', 'is'],
  role: ['require', 'check', 'ensure', 'has'],
  roles: ['require', 'check', 'ensure', 'has'],
  permission: ['require', 'check', 'ensure', 'has'],
  permissions: ['require', 'check', 'ensure', 'has'],
  admin: ['is', 'require', 'check', 'ensure', 'only'],
  staff: STAFF_VERBS,
  superuser: STAFF_VERBS,
  superadmin: STAFF_VERBS,
  backoffice: STAFF_VERBS,
  moderator: STAFF_VERBS,
};

// Words that mean the identifier is a router/handler, not a guard (`authRoutes`).
const NOT_GUARD_WORDS = new Set([
  'router',
  'routers',
  'route',
  'routes',
  'routing',
  'controller',
  'controllers',
  'callback',
  'callbacks',
  'limiter',
  'limiters',
  'limit',
  'throttle',
  'ratelimit',
  'ratelimiter',
  'validation',
  'validator',
  'validators',
  'schema',
  'rules',
]);

// Run-together lowercase names that cannot be split into words.
const FLAT_NAMES = new Set([
  'requireauth',
  'checkauth',
  'isauthenticated',
  'ensureauthenticated',
  'ensureloggedin',
  'isloggedin',
  'requirelogin',
  'requireuser',
  'requirerole',
  'verifytoken',
  'checktoken',
  'isadmin',
  'requireadmin',
  'isstaff',
  'requirestaff',
  'issuperuser',
  'requiresuperuser',
]);

// `auth.<one of these>` is a guard; `auth.optional` is deliberately not.
const GUARD_MEMBERS = new Set(['required', 'protect', 'authenticate', 'verify', 'check', 'middleware', 'guard']);

export function splitWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

export function isAuthMiddlewareName(name: string): boolean {
  const words = splitWords(name);
  if (!words.length || words.some((w) => NOT_GUARD_WORDS.has(w))) return false;
  if (words.length === 1 && FLAT_NAMES.has(words[0]!)) return true;
  // `validateAuth` / `validateLogin` validate a payload; only validateToken/validateSession check credentials.
  if (words.includes('validate') && !words.includes('token') && !words.includes('session')) return false;
  if (words.some((w) => GUARD_WORDS.has(w))) return true;
  for (const [noun, verbs] of Object.entries(NOUN_VERBS)) {
    if (words.includes(noun) && words.some((w) => verbs.includes(w))) return true;
  }
  return words.includes('api') && words.includes('key') && words.some((w) => CHECK_VERBS.includes(w));
}

function unwrap(node: Node): Node {
  let n = node;
  while (n.type === 'TSAsExpression' || n.type === 'TSNonNullExpression' || n.type === 'ParenthesizedExpression') {
    n = n.expression;
  }
  return n;
}

function memberChain(node: Node): string[] | null {
  const n = unwrap(node);
  if (n.type === 'Identifier') return [n.name];
  if (n.type === 'MemberExpression' && !n.computed && n.property.type === 'Identifier') {
    const base = memberChain(n.object);
    return base ? [...base, n.property.name] : null;
  }
  return null;
}

/** Words a guard expression exposes as evidence: callee name (and `auth` of `auth.required`), plus string-literal call arguments. */
export function guardEvidenceNames(node: Node): string[] {
  const n = unwrap(node);
  if (n.type === 'ArrayExpression') {
    return n.elements.flatMap((e) => (e !== null && e.type !== 'SpreadElement' && isAuthMiddleware(e) ? guardEvidenceNames(e) : []));
  }
  const chain = memberChain(n.type === 'CallExpression' ? n.callee : n);
  if (!chain) return [];
  const names = [chain[chain.length - 1]!];
  if (chain.length > 1 && isAuthMiddlewareName(chain[0]!)) names.push(chain[0]!);
  if (n.type === 'CallExpression') {
    for (const arg of n.arguments) {
      const items = arg.type === 'ArrayExpression' ? arg.elements : [arg];
      for (const item of items) if (item?.type === 'StringLiteral' && item.value) names.push(item.value);
    }
  }
  return names;
}

/** True if an expression (identifier, member, call, or array of them) is a recognised auth middleware. */
export function isAuthMiddleware(node: Node): boolean {
  const n = unwrap(node);
  if (n.type === 'ArrayExpression') {
    return n.elements.some((e) => e !== null && e.type !== 'SpreadElement' && isAuthMiddleware(e));
  }
  const target = n.type === 'CallExpression' ? n.callee : n;
  const chain = memberChain(target);
  if (!chain) return false;
  const last = chain[chain.length - 1]!;
  if (isAuthMiddlewareName(last)) return true;
  // auth.required, auth.protect(), ...
  return chain.length > 1 && isAuthMiddlewareName(chain[0]!) && GUARD_MEMBERS.has(last);
}

// Words that mark a decorator/dependency as explicitly NOT an access check (`Public`, `OptionalAuth`, `SkipAuth`).
const OPEN_WORDS = new Set(['public', 'optional', 'skip', 'allow', 'anonymous', 'anon', 'bypass', 'exempt', 'noauth', 'unauthenticated', 'unprotected']);

// Guard classes that limit traffic or shape requests rather than check who the caller is.
const NON_ACCESS_GUARDS = new Set(['throttle', 'throttler', 'ratelimit', 'ratelimiter', 'limiter', 'limit', 'cache', 'feature', 'flag', 'flags', 'csrf', 'xsrf', 'validation']);

const ACCESS_WORDS = new Set(['role', 'roles', 'permission', 'permissions', 'scope', 'scopes', 'policy', 'policies', 'ability', 'abilities', 'acl', 'rbac', 'admin', 'staff', 'superuser', 'owner']);

/** NestJS `@Public()` / `@SkipAuth()` style decorator: the route opts out of the access check. */
export function isOpenAccessName(name: string): boolean {
  const words = splitWords(name);
  return words.some((w) => OPEN_WORDS.has(w)) && !words.some((w) => NOT_GUARD_WORDS.has(w));
}

/** NestJS guard class (`AuthGuard`, `JwtAuthGuard`, `RolesGuard`, `AdminGuard`); not a throttler, cache or CSRF guard. */
export function isNestGuardName(name: string): boolean {
  const words = splitWords(name);
  if (!words.length || words.some((w) => OPEN_WORDS.has(w) || NON_ACCESS_GUARDS.has(w) || NOT_GUARD_WORDS.has(w))) return false;
  if (isAuthMiddlewareName(name)) return true;
  return words.includes('guard') && words.some((w) => ACCESS_WORDS.has(w));
}

/** NestJS role/permission decorator (`@Roles('admin')`, `@Permissions(...)`, `@Auth()`, `@RequireRole()`). */
export function isNestAccessDecorator(name: string): boolean {
  const words = splitWords(name);
  if (!words.length || words.some((w) => OPEN_WORDS.has(w))) return false;
  if (isAuthMiddlewareName(name)) return true;
  return words.some((w) => ACCESS_WORDS.has(w) && w !== 'owner');
}

const PY_ACCESS_WORDS = new Set([
  'auth',
  'authn',
  'authz',
  'authenticate',
  'authenticated',
  'authentication',
  'authorize',
  'authorized',
  'authorization',
  'login',
  'logged',
  'jwt',
  'token',
  'oauth',
  'oauth2',
  'bearer',
  'basic',
  'key',
  'admin',
  'staff',
  'superuser',
  'role',
  'roles',
  'permission',
  'permissions',
  'scope',
  'scopes',
  'rbac',
  'acl',
  'principal',
]);

const PY_REQUIRE_WORDS = new Set(['required', 'require', 'requires', 'only', 'protected', 'accepted', 'needed']);

/** A FastAPI dependency (`Depends(get_current_user)`, `Depends(auth)`, `Security(verify_token)`) that checks who the caller is; `get_db`, `rate_limit` and friends are not. */
export function isPyAuthDependency(name: string): boolean {
  const words = splitWords(name);
  if (!words.length || words.some((w) => OPEN_WORDS.has(w) || NOT_GUARD_WORDS.has(w) || NON_ACCESS_GUARDS.has(w))) return false;
  if (isAuthMiddlewareName(name)) return true;
  if (words.includes('current') && words.some((w) => ['user', 'admin', 'staff', 'superuser', 'account', 'principal', 'member'].includes(w))) return true;
  return words.some((w) => PY_ACCESS_WORDS.has(w) && w !== 'key' && w !== 'basic') || (words.includes('api') && words.includes('key'));
}

/** Flask/Python route decorator that requires a logged-in or privileged caller (`login_required`, `admin_required`, `jwt_required`, `roles_required`). */
export function isPyGuardDecorator(name: string): boolean {
  const words = splitWords(name);
  if (!words.length || words.some((w) => OPEN_WORDS.has(w))) return false;
  const access = words.some((w) => PY_ACCESS_WORDS.has(w)) || (words.includes('api') && words.includes('key'));
  return access && words.some((w) => PY_REQUIRE_WORDS.has(w));
}
