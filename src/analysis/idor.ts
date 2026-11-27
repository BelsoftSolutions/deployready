/**
 * Static IDOR / broken object-level authorization (BOLA) check, per route handler.
 *
 * Pure, no I/O. A handler is reported only when ALL of these hold:
 *  (a) the route path takes an object id (`:id`, `{item_id}`, `<int:id>`, `[id]`),
 *  (b) the handler loads, updates or deletes ONE record by that id alone
 *      (Prisma/Sequelize `where: { id }`, Mongoose `findById*`, Sequelize `findByPk`,
 *      SQL `WHERE id = ?`, Supabase `.eq('id', …)` on a service-role client,
 *      SQLAlchemy `get` / `filter_by(id=)` / `filter(M.id == …)`),
 *  (c) the handler knows who the caller is (auth middleware, `req.user`, `getServerSession()`,
 *      `auth()`, `Depends(get_current_user)`, `@login_required`, …), and
 *  (d) nothing in the handler ties the record to that caller: no owner/user/tenant field,
 *      no use of the caller's id, no ownership/permission helper, and no admin/role guard.
 *
 * Precision over recall: any sign of scoping (even one we cannot prove is correct) silences
 * the handler; unauthenticated handlers are left to `missing-auth-route`; public catalog reads
 * (products, posts, …) are skipped; Supabase lookups through the user's own client are left
 * to RLS. A live two-user test (`--active --token … --token-b …`) proves or clears a finding.
 */
import type { Route } from '../types';
import { ADMIN_PATH_RE, handlerRange } from './routeAuth';

export interface IdorIssue {
  route: Route;
  /** 1-based line of the lookup. */
  line: number;
  /** The lookup line, trimmed (callers redact and truncate). */
  evidence: string;
  /** The path parameter the id comes from. */
  param: string;
  /** Whether the lookup changes the record (update/delete) or only reads it. */
  op: 'read' | 'write';
  severity: 'critical' | 'warning';
}

/** Max handler lines (from the route line) to inspect. */
const WINDOW = 60;
/** Max lines of a Next.js / pages/api handler to inspect. */
const MODULE_WINDOW = 120;

const ID_NAME_RE = /^(?:id|_id|pk|uuid|\w+_id|\w+Id|\w+ID)$/;
const PARAM_RE = /:(\w+)|\{(\w+)(?::[^}]{0,40})?\}|<(?:\w+:)?(\w+)>|\[(\w+)\]/g;

/** The caller's identity is available in the handler. */
const IDENTITY_RE = new RegExp(
  [
    '\\bDepends\\s*\\(\\s*\\w*(?:user|auth|token|login|session|jwt|verify|principal|account)\\w*',
    '\\bSecurity\\s*\\(',
    '@\\w*(?:login|auth|jwt|token)_required\\b',
    '\\bcurrent_user\\b',
    '\\bcurrentUser\\b',
    '\\bgetServerSession\\s*\\(',
    '\\bgetServerAuthSession\\s*\\(',
    '\\bauth\\s*\\(\\s*\\)',
    '\\bgetAuth\\s*\\(',
    '\\.auth\\.get(?:User|Session)\\s*\\(',
    '\\breq\\.(?:user|auth)\\b',
    '\\brequest\\.(?:user|state\\.user)\\b',
    '\\bg\\.user\\b',
    '\\bsession\\??\\.user\\b',
    '\\bjwt\\.verify\\s*\\(',
    '\\bverifyToken\\s*\\(',
    '\\b(?:require|ensure|with)(?:Auth|User|Login|Session)\\w*\\b',
    '\\bisAuthenticated\\b',
  ].join('|'),
  'i',
);

/** Anything that looks like the record is scoped to, or checked against, the caller. */
const OWNER_FIELD_RE =
  /\b(?:user_?id|owner\w*|author_?id|tenant_?id|org(?:anization)?_?id|account_?id|team_?id|workspace_?id|created_?by|customer_?id|profile_?id|member_?id|company_?id)\b|own(?:er|ership)/i;
const IDENTITY_USE_RE =
  /\b(?:user|me|current_?user|currentUser|auth|claims|payload|decoded|token|principal|viewer)\s*(?:\?\.|\.|\[\s*['"])\s*(?:id|_id|sub|uid|pk|email)\b|\bauth\.uid\s*\(|\bgetUserId\s*\(/i;
const PERMISSION_RE =
  /\b(?:can|authori[sz]e|ability|policy|permit|has_?perm\w*|has_?access|check_?access|access_?control)\w*\s*\(/i;
/** Admin / role guards: these routes are meant to reach any record. */
const ROLE_RE =
  /\b(?:is_?admin|require_?admin|admin_required|admin_?only|require_?role\w*|has_?role\w*|roles?|is_superuser|is_staff|superuser|permissions?|admin)\b|\.admin\b/i;

/** Public catalog resources: reading one by id is normal. */
const PUBLIC_RESOURCE_RE =
  /^(?:products?|posts?|articles?|blogs?|categor(?:y|ies)|tags?|pages?|docs?|courses?|lessons?|events?|listings?|recipes?|plans?|faqs?|public|shop|catalog|menus?|stores?|reviews?|comments?)$/i;

const SUPABASE_PRIVILEGED_RE = /service_role|SERVICE_ROLE|supabaseAdmin|createAdminClient|adminClient/;

const WRITE_RE =
  /\b(?:update|updateOne|updateMany|delete|deleteOne|destroy|remove|upsert|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findOneAndUpdate|findOneAndDelete)\b/;
const SQL_WRITE_RE = /\bupdate\s+[\w."`]+\s+set\b|\bdelete\s+from\b/i;
const SQL_ID_WHERE_RE =
  /\bwhere\s+(?:\w+\.)?["`]?(?:id|_id)["`]?\s*=\s*(?:\?|\$1|%s|%\(\w+\)s|:\w+|@\w+)(?!\s*(?:and|or)\b)/i;

const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Id-like path parameters of a route path. */
export function idParams(routePath: string): string[] {
  const out: string[] = [];
  for (const m of routePath.matchAll(PARAM_RE)) {
    const name = m[1] ?? m[2] ?? m[3] ?? m[4];
    if (name && ID_NAME_RE.test(name) && !out.includes(name)) out.push(name);
  }
  return out;
}

/** The path segment just before the (last) id parameter: the resource name. */
function resourceBefore(routePath: string, param: string): string | undefined {
  const segs = routePath.split('/').filter(Boolean);
  const i = segs.findIndex((s) => s.includes(param) && /[:{<[]/.test(s));
  return i > 0 ? segs[i - 1] : undefined;
}

/** Source text that refers to the parameter `n`: request members, plus local aliases. */
function paramRefs(n: string, text: string, python: boolean, pagesApi: boolean): string[] {
  const e = esc(n);
  const refs = [
    `\\b(?:req|request)\\.params\\??\\.${e}\\b`,
    `\\b(?:req|request)\\.params\\[\\s*['"]${e}['"]\\s*\\]`,
    `\\b(?:params|context\\.params|ctx\\.params)\\??\\.${e}\\b`,
    `\\(\\s*await\\s+(?:params|context\\.params|ctx\\.params)\\s*\\)\\??\\.${e}\\b`,
    `\\bc\\.req\\.param\\(\\s*['"]${e}['"]\\s*\\)`,
    `\\brequest\\.path_params\\[\\s*['"]${e}['"]\\s*\\]`,
  ];
  if (pagesApi) refs.push(`\\breq\\.query\\??\\.${e}\\b`, `\\breq\\.query\\[\\s*['"]${e}['"]\\s*\\]`);
  const bare = (name: string) => `(?<![\\w.$])${esc(name)}\\b(?!\\s*:)`;
  // Python handlers receive path parameters as function arguments.
  if (python) return [...refs, bare(n)];

  const member = new RegExp(refs.join('|'));
  const aliases = new Set<string>();
  // const { id } = req.params / await params;  ({ params: { id } }) in a signature.
  const destructure =
    /\{([^{}=]{1,200})\}\s*(?::[^=;\n]{0,200})?=\s*(?:await\s+)?(?:req\.params|request\.params|params|context\.params|ctx\.params|req\.query)\b|\bparams\s*:\s*\{([^{}]{1,200})\}\s*\}\s*[:)]/g;
  for (const m of text.matchAll(destructure)) {
    for (const part of (m[1] ?? m[2] ?? '').split(',')) {
      const [left, right] = part.split(':').map((x) => x.trim());
      if (left !== n) continue;
      if (right && /^[A-Za-z_$][\w$]*$/.test(right) && !/^(?:string|number|any|unknown)$/.test(right)) aliases.add(right);
      else aliases.add(n);
    }
  }
  // const orderId = req.params.id / Number(params.id)
  for (const line of text.split('\n')) {
    const m = /^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*\w+\s*)?=\s*([^;\n]{1,160})/.exec(line);
    if (m && member.test(m[2]!)) aliases.add(m[1]!);
  }
  return [...refs, ...[...aliases].map(bare)];
}

interface Lookup {
  line: number;
  evidence: string;
  op: 'read' | 'write';
}

/** First line in `lines` that looks up one record by the id alone. */
function findLookup(lines: string[], offset: number, refs: string[], supabaseOk: boolean, bareId: boolean): Lookup | undefined {
  const V =
    '(?:(?:Number|parseInt|String|BigInt|int|str|UUID|uuid\\.UUID|ObjectId|new\\s+ObjectId|Types\\.ObjectId|mongoose\\.Types\\.ObjectId)\\s*\\(\\s*)?\\+?\\s*(?:' +
    refs.join('|') +
    ')';
  const END = '\\s*\\)?\\s*(?:as\\s+\\w+\\s*)?,?\\s*\\}';
  const patterns = [
    // Prisma / Sequelize / TypeORM: where: { id: <param> } with no other key
    `\\bwhere\\s*:\\s*\\{\\s*(?:id|_id)\\s*:\\s*${V}${END}`,
    // TypeORM findOneBy({ id }), Mongoose findOne({ _id: id })
    `\\.(?:findOneBy|findOne|findOneAndUpdate|findOneAndDelete|deleteOne|updateOne)\\s*\\(\\s*\\{\\s*(?:id|_id)\\s*:\\s*${V}${END}`,
    // Mongoose
    `\\.findById(?:AndUpdate|AndDelete|AndRemove)?\\s*\\(\\s*${V}\\s*[,)]`,
    // Sequelize
    `\\.findByPk\\s*\\(\\s*${V}\\s*[,)]`,
    // SQLAlchemy / Flask-SQLAlchemy / Django
    `\\bquery(?:\\(\\s*[\\w.]+\\s*\\))?\\.get(?:_or_404)?\\s*\\(\\s*${V}\\s*\\)`,
    `\\b(?:db|session|db\\.session|self\\.session)\\.get(?:_or_404)?\\s*\\(\\s*[\\w.]+\\s*,\\s*${V}\\s*\\)`,
    `\\.filter_by\\s*\\(\\s*(?:id|pk)\\s*=\\s*${V}\\s*\\)`,
    `\\.filter\\s*\\(\\s*[\\w.]+\\.id\\s*==\\s*${V}\\s*\\)`,
    `\\bobjects\\.get\\s*\\(\\s*(?:id|pk)\\s*=\\s*${V}\\s*\\)`,
    `\\bget_object_or_404\\s*\\(\\s*[\\w.]+\\s*,\\s*(?:id|pk)\\s*=\\s*${V}\\s*\\)`,
  ];
  if (bareId) patterns.push('\\bwhere\\s*:\\s*\\{\\s*id\\s*,?\\s*\\}', '\\.(?:findOneBy|findOne)\\s*\\(\\s*\\{\\s*id\\s*\\}\\s*\\)');
  if (supabaseOk) patterns.push(`\\.eq\\s*\\(\\s*['"]id['"]\\s*,\\s*${V}\\s*\\)?\\s*\\)`);
  const lookupRe = new RegExp(patterns.join('|'));
  const refRe = new RegExp(refs.join('|'));

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.length > 400 || /^\s*(?:\/\/|#|\*)/.test(line)) continue;
    if (lookupRe.test(line)) {
      // The same statement, or the next few lines (`obj = get(id)` then `db.delete(obj)`).
      const near = lines.slice(Math.max(0, i - 3), i + 6).join('\n');
      return { line: offset + i + 1, evidence: line.trim(), op: WRITE_RE.test(near) ? 'write' : 'read' };
    }
    // Parameterized SQL: WHERE id = ? with the parameter bound on this line or the next two.
    if (SQL_ID_WHERE_RE.test(line) && !/\$\{/.test(line) && refRe.test(lines.slice(i, i + 3).join('\n'))) {
      const stmt = lines.slice(Math.max(0, i - 2), i + 1).join('\n');
      return { line: offset + i + 1, evidence: line.trim(), op: SQL_WRITE_RE.test(stmt) ? 'write' : 'read' };
    }
  }
  return undefined;
}

/** [from, to) line range of the handler for this route, or undefined when it cannot be located. */
function handlerLines(route: Route, lines: string[]): [number, number] | undefined {
  const nextRoute = /(?:^|\/)route\.[jt]sx?$/.test(route.file);
  if (nextRoute) {
    const m = route.method.toUpperCase();
    const start = lines.findIndex((l) =>
      new RegExp(`^\\s*export\\s+(?:async\\s+)?function\\s+${m}\\b|^\\s*export\\s+const\\s+${m}\\s*=`).test(l),
    );
    if (start < 0) return undefined;
    let end = start + 1;
    while (end < lines.length && end - start < MODULE_WINDOW && !/^\s*export\s/.test(lines[end]!)) end++;
    return [start, end];
  }
  if (/(?:^|\/)pages\/api\//.test(route.file)) return [0, Math.min(lines.length, MODULE_WINDOW)];
  if (!route.line) return undefined;
  return handlerRange(route.line, lines, WINDOW);
}

/**
 * Project-level signal that records belong to someone: an owner/user/tenant column or field in
 * code, SQL or a schema. Without one there is no ownership to check (single-tenant or shared data).
 */
export const OWNERSHIP_MODEL_RE =
  /\b(?:user_?id|owner_?id|author_?id|tenant_?id|org(?:anization)?_?id|account_?id|team_?id|workspace_?id|created_?by|customer_?id)\b/i;

/**
 * Handler ranges for a route. Flask's parser output merges `@app.route(path)` and
 * `@app.route(path, methods=[...])` into one route, so for Python every handler declared with
 * the same path literal in the file is checked.
 */
function handlerRanges(route: Route, lines: string[]): Array<[number, number]> {
  const first = handlerLines(route, lines);
  const out = first ? [first] : [];
  if (!/\.py$/i.test(route.file) || !route.line) return out;
  const decl = new RegExp(`^\\s*@[\\w.]+\\.(?:route|get|post|put|patch|delete|api_route)\\s*\\(\\s*["']${esc(route.path)}["']`);
  for (let i = 0; i < lines.length; i++) {
    if (i === route.line - 1 || !decl.test(lines[i]!)) continue;
    const range = handlerRange(i + 1, lines, WINDOW);
    if (!out.some(([a]) => a === range[0])) out.push(range);
  }
  return out;
}

/** The handler's HTTP methods: the route's own, or (Flask) the decorator's methods=[...] list. */
function handlerMethods(route: Route, decorators: string): string[] {
  const m = /methods\s*=\s*[[(]([^\])]{0,120})[\])]/.exec(decorators);
  if (m) return [...m[1]!.matchAll(/["'](\w+)["']/g)].map((x) => x[1]!.toUpperCase());
  const verb = /@[\w.]+\.(get|post|put|patch|delete)\s*\(/i.exec(decorators);
  return [verb ? verb[1]!.toUpperCase() : route.method.toUpperCase()];
}

function checkHandler(r: Route, params: string[], source: string, lines: string[], range: [number, number]): IdorIssue | undefined {
  const body = lines.slice(range[0], range[1]);
  const text = body.join('\n');
  if (!r.guarded && !IDENTITY_RE.test(text)) return undefined; // anonymous: missing-auth-route's job
  if (ROLE_RE.test(text) || (r.guardNames ?? []).some((g) => /admin|role|perm/i.test(g))) return undefined;

  const python = /\.py$/i.test(r.file);
  const pagesApi = /(?:^|\/)pages\/api\//.test(r.file);
  const supabaseOk = SUPABASE_PRIVILEGED_RE.test(source);
  const decorators = body.filter((l) => /^\s*@/.test(l)).join('\n');
  const methods = python ? handlerMethods(r, decorators) : [r.method.toUpperCase()];
  const readOnly = methods.every((m) => m === 'GET' || m === 'HEAD');

  for (const param of params) {
    if (readOnly && PUBLIC_RESOURCE_RE.test(resourceBefore(r.path, param) ?? '')) continue;
    const refs = paramRefs(param, text, python, pagesApi);
    const bareId = refs.some((x) => x.startsWith('(?<![\\w.$])id\\b'));
    const hit = findLookup(body, range[0], refs, supabaseOk, bareId);
    if (!hit) continue;

    // Scoping signals, with the id parameter itself blanked so `/users/:userId` is not "scoped".
    const scoped = text.replace(new RegExp(refs.join('|'), 'g'), '__param__');
    if (OWNER_FIELD_RE.test(scoped) || IDENTITY_USE_RE.test(scoped) || PERMISSION_RE.test(scoped)) return undefined;

    const mutatingMethod = methods.some((m) => m === 'DELETE' || m === 'PUT' || m === 'PATCH');
    const severity = mutatingMethod || (hit.op === 'write' && !readOnly) ? 'critical' : 'warning';
    return { route: r, line: hit.line, evidence: hit.evidence, param, op: hit.op, severity };
  }
  return undefined;
}

/**
 * `ownershipModel`: whether the project models per-user/tenant ownership anywhere (see
 * OWNERSHIP_MODEL_RE); defaults to scanning `sources`.
 */
export function idorIssues(routes: Route[], sources: Map<string, string>, ownershipModel?: boolean): IdorIssue[] {
  const out: IdorIssue[] = [];
  if (!(ownershipModel ?? [...sources.values()].some((s) => OWNERSHIP_MODEL_RE.test(s)))) return out;
  const seen = new Set<string>();

  for (const r of routes) {
    if (r.source === 'openapi') continue;
    const source = sources.get(r.file);
    if (!source) continue;
    const params = idParams(r.path);
    if (params.length === 0 || ADMIN_PATH_RE.test(r.path)) continue;
    const lines = source.split('\n');
    for (const range of handlerRanges(r, lines)) {
      const issue = checkHandler(r, params, source, lines, range);
      if (!issue || seen.has(`${r.file}:${issue.line}`)) continue;
      seen.add(`${r.file}:${issue.line}`);
      out.push(issue);
    }
  }
  return out;
}
