/**
 * Supabase object checks on the replayed migration model (final state only), beyond table RLS:
 *
 *  - Storage: public buckets that look private; `storage.objects` policies that let anon / any
 *    signed-in user read or write a whole bucket (only `bucket_id = 'x'`, no owner check).
 *  - Functions: SECURITY DEFINER functions without `SET search_path` (CWE-426); SECURITY DEFINER
 *    functions in an exposed schema that anon / authenticated may EXECUTE (Postgres grants EXECUTE
 *    to PUBLIC, Supabase to anon and authenticated), and the ones among them that read or write an
 *    RLS-protected table without looking at the caller: they bypass RLS for every caller.
 *  - Views: views in an exposed schema over RLS-protected tables without `security_invoker`
 *    (PG15+), and materialized views there: they run as their owner, so RLS does not apply.
 *  - Triggers: SECURITY DEFINER trigger functions that copy caller-controlled values
 *    (`new.raw_user_meta_data`, `new.role`, ...) into a role / admin table.
 *  - Realtime: sensitive tables in the `supabase_realtime` publication with no RLS or an open
 *    SELECT policy, so every change is broadcast to any subscriber.
 *  - Grants: ALTER DEFAULT PRIVILEGES and `GRANT ... ON ALL TABLES IN SCHEMA` giving anon write
 *    access beyond Supabase's own defaults, and column-level grants that expose secret or personal
 *    columns of rows the role can read.
 *
 * Pure, no I/O. Severity follows data sensitivity (table, bucket and column names, project config).
 */
import { splitStatements, tokenize, type Token } from './lexer';
import { alwaysTrueFor, identValue, type Expr, type Role } from './expr';
import { appliesTo, clauseFor, coversCommand, COMMANDS, DEFAULT_EXPOSED, hasPrivilege, openings, ROLES } from './access';
import { tableKey, triggerFunction, type DbModel, type FunctionState, type PolicyCommand, type PolicyState, type TableState, type ViewState } from './model';
import { classifyBucket, classifyTable, columnSensitivity, words, type RlsProjectConfig, type Sensitivity } from './sensitivity';

export type DeepSeverity = 'critical' | 'warning' | 'info';

export interface DeepIssue {
  rule: string;
  title: string;
  severity: DeepSeverity;
  file: string;
  line: number;
  cwe: string;
  description: string;
  recommendation: string;
  /** The object the issue is about, e.g. `public.get_invoices` or `storage bucket "kyc"`. */
  object: string;
}

export interface DeepOptions {
  config?: RlsProjectConfig;
  /** The project is clearly Supabase (anon / authenticated / storage / realtime exist). */
  supabase?: boolean;
}

/** Schemas owned by Supabase / Postgres: their functions are not the project's code. */
const SYSTEM_SCHEMAS = new Set([
  'auth', 'storage', 'extensions', 'realtime', 'graphql', 'graphql_public', 'vault', 'pgsodium', 'pgsodium_masks', 'net',
  'supabase_functions', 'supabase_migrations', 'cron', 'pgbouncer', 'pg_catalog', 'information_schema', '_realtime', '_analytics',
]);

const qn = (schema: string, name: string): string => `${schema}.${name}`;
const alive = (model: DbModel, t: TableState): boolean => model.tables.get(tableKey(t.schema, t.name)) === t;
const RANK: Record<Sensitivity, number> = { sensitive: 2, unknown: 1, public: 0 };

function exposedSet(cfg: RlsProjectConfig): Set<string> {
  return new Set((cfg.exposedSchemas ?? DEFAULT_EXPOSED).map((s) => s.trim().replace(/"/g, '')));
}

function who(roles: Role[]): string {
  return roles.map((r) => (r === 'anon' ? 'anyone with your public anon key (no sign-in)' : 'any signed-in user')).join(' and ');
}

// ------------------------------------------------------------------ storage

/** Replace `bucket_id = '<id>'` / `bucket_id in (...)` with TRUE when it selects `chosen`, FALSE otherwise. */
function forBucket(e: Expr | null, chosen: string | null): Expr | null {
  if (!e) return e;
  const isBucketCol = (x: Expr): boolean => x.k === 'col' && x.parts[x.parts.length - 1] === 'bucket_id';
  const lit = (x: Expr): string | null => (x.k === 'const' && typeof x.v === 'string' ? x.v : x.k === 'cast' ? lit(x.e) : null);
  switch (e.k) {
    case 'bin': {
      if (e.op === '=' && ((isBucketCol(e.l) && lit(e.r) !== null) || (isBucketCol(e.r) && lit(e.l) !== null))) {
        const v = lit(isBucketCol(e.l) ? e.r : e.l);
        return { k: 'const', v: chosen !== null && v === chosen };
      }
      return { ...e, l: forBucket(e.l, chosen)!, r: forBucket(e.r, chosen)! };
    }
    case 'in':
      if (isBucketCol(e.e) && e.list && e.list.every((x) => lit(x) !== null)) {
        const hit = chosen !== null && e.list.some((x) => lit(x) === chosen);
        return { k: 'const', v: e.neg ? !hit : hit };
      }
      return e;
    case 'and':
    case 'or':
      return { ...e, args: e.args.map((a) => forBucket(a, chosen)!) };
    case 'not':
      return { ...e, e: forBucket(e.e, chosen)! };
    case 'cast':
      return { ...e, e: forBucket(e.e, chosen)! };
    default:
      return e;
  }
}

function bucketsNamed(e: Expr | null, out = new Set<string>()): Set<string> {
  if (!e) return out;
  const lit = (x: Expr): string | null => (x.k === 'const' && typeof x.v === 'string' ? x.v : x.k === 'cast' ? lit(x.e) : null);
  const isBucketCol = (x: Expr): boolean => x.k === 'col' && x.parts[x.parts.length - 1] === 'bucket_id';
  switch (e.k) {
    case 'bin':
      if (isBucketCol(e.l) && lit(e.r) !== null) out.add(lit(e.r)!);
      else if (isBucketCol(e.r) && lit(e.l) !== null) out.add(lit(e.l)!);
      bucketsNamed(e.l, out);
      bucketsNamed(e.r, out);
      break;
    case 'in':
      if (isBucketCol(e.e)) e.list?.forEach((x) => lit(x) !== null && out.add(lit(x)!));
      break;
    case 'and':
    case 'or':
      e.args.forEach((a) => bucketsNamed(a, out));
      break;
    case 'not':
    case 'cast':
      bucketsNamed(e.e, out);
      break;
    default:
      break;
  }
  return out;
}

interface StorageOpening {
  role: Role;
  cmd: Exclude<PolicyCommand, 'all'>;
  bucket: string | null;
}

function storageChecks(model: DbModel, cfg: RlsProjectConfig, out: DeepIssue[]): void {
  for (const b of model.buckets.values()) {
    if (!b.public) continue;
    const v = classifyBucket(b.id, cfg);
    if (v.level === 'public') continue;
    out.push({
      rule: 'storage-bucket-public',
      title: v.level === 'sensitive' ? `Storage bucket "${b.id}" is public but looks private` : `Storage bucket "${b.id}" is public — review required: is that intended?`,
      severity: v.level === 'sensitive' ? 'critical' : 'warning',
      file: b.loc.file,
      line: b.loc.line,
      cwe: 'CWE-284',
      object: `storage bucket "${b.id}"`,
      description:
        `Anyone who has or guesses a file's path can download it from "${b.id}" without signing in: for a public bucket, Storage serves ` +
        `GET /storage/v1/object/public/${b.id}/<path> to everyone and does not check any policy on storage.objects. ` +
        `Paths are often predictable (user id + file name). ${v.level === 'sensitive' ? `The bucket name suggests private files (${v.reason}).` : 'DeployReady cannot tell whether these files are meant to be public; list the bucket under publicBuckets or sensitiveBuckets in .deployready.json to settle it.'} ` +
        'This is the final state after replaying the migrations in order.',
      recommendation:
        `Make the bucket private and hand out signed URLs: update storage.buckets set public = false where id = '${b.id}'; then add an owner-scoped read policy, e.g. ` +
        `create policy "owners read ${b.id}" on storage.objects for select to authenticated using (bucket_id = '${b.id}' and (storage.foldername(name))[1] = (select auth.uid())::text); ` +
        'and serve files with createSignedUrl().',
    });
  }

  const objects = model.tables.get(tableKey('storage', 'objects'));
  if (!objects) return;
  const known = [...model.buckets.keys()];
  const bucketVerdict = (id: string | null): { level: Sensitivity; reason: string } => {
    if (id !== null) return classifyBucket(id, cfg);
    // No bucket filter: the policy covers every bucket.
    let best: { level: Sensitivity; reason: string } = { level: 'unknown', reason: 'the policy applies to every bucket' };
    for (const k of known) {
      const v = classifyBucket(k, cfg);
      if (RANK[v.level] > RANK[best.level]) best = { level: v.level, reason: `the policy applies to every bucket, including "${k}" (${v.reason})` };
    }
    return best;
  };
  const restrictive = [...objects.policies.values()].filter((q) => !q.permissive);
  for (const p of objects.policies.values()) {
    if (!p.permissive) continue;
    const opens: StorageOpening[] = [];
    for (const role of ROLES) {
      if (!appliesTo(p, role)) continue;
      for (const cmd of COMMANDS) {
        if (!coversCommand(p, cmd)) continue;
        const cl = clauseFor(p, cmd);
        if (!cl.present) continue;
        const named = [...bucketsNamed(cl.expr)];
        const candidates: (string | null)[] = named.length ? named : [null];
        for (const bucket of candidates) {
          if (!alwaysTrueFor(forBucket(cl.expr, bucket), { role })) continue;
          // A restrictive policy we cannot prove true for this bucket closes the gap.
          const closed = restrictive.some((q) => appliesTo(q, role) && coversCommand(q, cmd) && clauseFor(q, cmd).present && !alwaysTrueFor(forBucket(clauseFor(q, cmd).expr, bucket), { role }));
          if (!closed) opens.push({ role, cmd, bucket });
        }
      }
    }
    if (!opens.length) continue;
    let severity: DeepSeverity | null = null;
    const bump = (s: DeepSeverity): void => {
      if (!severity || (s === 'critical') || (s === 'warning' && severity === 'info')) severity = s;
    };
    const reasons = new Set<string>();
    for (const o of opens) {
      const v = bucketVerdict(o.bucket);
      const isPublicBucket = o.bucket !== null && model.buckets.get(o.bucket)?.public === true;
      if (o.cmd === 'select') {
        if (v.level === 'public' || (isPublicBucket && v.level !== 'sensitive')) continue;
        bump(v.level === 'sensitive' ? 'critical' : 'warning');
      } else if (o.role === 'anon') {
        bump(v.level === 'public' ? 'warning' : 'critical');
      } else if (o.cmd === 'insert') {
        if (v.level === 'public') continue;
        bump('warning');
      } else {
        bump(v.level === 'sensitive' ? 'critical' : 'warning');
      }
      reasons.add(v.reason);
    }
    if (!severity) continue;
    const roles = [...new Set(opens.map((o) => o.role))];
    const cmds = [...new Set(opens.map((o) => o.cmd.toUpperCase()))];
    const buckets = [...new Set(opens.map((o) => o.bucket))];
    const bucketText = buckets.includes(null) ? 'every bucket' : buckets.map((b) => `"${b}"`).join(', ');
    const anyWrite = opens.some((o) => o.cmd !== 'select');
    const cl = clauseFor(p, opens[0]!.cmd);
    const example = buckets.find((b): b is string => b !== null) ?? 'documents';
    out.push({
      rule: 'storage-policy-permissive',
      title: `Storage policy "${p.name}" lets ${roles.join(' and ')} ${cmds.join('/')} every file in ${bucketText}`,
      severity,
      file: p.loc.file,
      line: p.loc.line,
      cwe: 'CWE-285',
      object: `storage.objects policy "${p.name}"`,
      description:
        `${who(roles)} can ${anyWrite ? 'read, upload, overwrite or delete' : 'list and download'} other users' files in ${bucketText}. ` +
        `Policy "${p.name}" on storage.objects (FOR ${p.command.toUpperCase()}) only checks the bucket — ${cl.label} (${cl.text}) — ` +
        'and never ties the file to its owner (owner / owner_id = auth.uid(), or the first folder of the path = auth.uid()). ' +
        `${[...reasons].join('; ')}. This is the final state after replaying the migrations in order.`,
      recommendation:
        `Scope the policy to the file's owner, e.g. ${anyWrite ? 'with check' : 'using'} (bucket_id = '${example}' and (storage.foldername(name))[1] = (select auth.uid())::text) ` +
        `or (bucket_id = '${example}' and owner_id = (select auth.uid())::text), and upload files under "<user id>/<file>". ` +
        'If the files are meant to be public (avatars, site assets), list the bucket under publicBuckets in .deployready.json.',
    });
  }
}

// ------------------------------------------------------------------ functions

interface BodyRef {
  table: TableState;
  write: boolean;
}

function pathList(f: FunctionState): string[] {
  if (f.searchPath === null) return f.createPath;
  return f.searchPath
    .split(',')
    .map((x) => x.trim().replace(/^"|"$/g, ''))
    .filter((x) => x && x !== "''" && x !== '$user');
}

/** Tables a function body reads (FROM / JOIN) or writes (INSERT INTO / UPDATE / DELETE FROM). */
function bodyRefs(model: DbModel, f: FunctionState): BodyRef[] {
  const toks = tokenize(f.body);
  const path = pathList(f);
  const out: BodyRef[] = [];
  const resolve = (k: number): { t: TableState; end: number } | null => {
    let j = k;
    if (toks[j]?.type === 'word' && toks[j]!.value === 'only') j++;
    const parts: string[] = [];
    const first = identValue(toks[j]);
    if (!first) return null;
    parts.push(first);
    j++;
    while (toks[j]?.type === 'punct' && toks[j]!.value === '.' && identValue(toks[j + 1])) {
      parts.push(identValue(toks[j + 1])!);
      j += 2;
    }
    if (parts.length >= 2) {
      const t = model.tables.get(tableKey(parts[parts.length - 2]!, parts[parts.length - 1]!));
      return t ? { t, end: j } : null;
    }
    for (const s of path) {
      const t = model.tables.get(tableKey(s, parts[0]!));
      if (t) return { t, end: j };
    }
    return null;
  };
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k]!;
    if (t.type !== 'word') continue;
    const prev = toks[k - 1];
    if (t.value === 'from' || t.value === 'join') {
      const write = t.value === 'from' && prev?.type === 'word' && prev.value === 'delete';
      const r = resolve(k + 1);
      if (r) out.push({ table: r.t, write });
    } else if (t.value === 'into' && prev?.type === 'word' && prev.value === 'insert') {
      const r = resolve(k + 1);
      if (r) out.push({ table: r.t, write: true });
    } else if (t.value === 'update' && !(prev?.type === 'word' && (prev.value === 'do' || prev.value === 'for'))) {
      const r = resolve(k + 1);
      if (r) out.push({ table: r.t, write: true });
    }
  }
  return out;
}

/** The body looks at who is calling: auth.uid(), auth.jwt(), auth.role(), current_user. */
function bodyChecksCaller(body: string): boolean {
  return /\bauth\s*\.\s*(?:uid|jwt|role)\s*\(|\bcurrent_user\b|\bsession_user\b|\bcurrent_setting\s*\(\s*'request\.jwt/i.test(body);
}

function fnSignature(f: FunctionState): string {
  return `${qn(f.schema, f.name)}(${f.args.replace(/\s+default\s+[^,]+/gi, '')})`;
}

function functionChecks(model: DbModel, cfg: RlsProjectConfig, exposed: Set<string>, out: DeepIssue[]): void {
  for (const f of model.functions.values()) {
    if (f.kind !== 'function' || !f.securityDefiner || SYSTEM_SCHEMAS.has(f.schema)) continue;
    const sig = fnSignature(f);
    const isTrigger = /^(?:trigger|event_trigger)\b/.test(f.returns);

    if (f.searchPath === null) {
      out.push({
        rule: 'security-definer-search-path',
        title: `SECURITY DEFINER function ${qn(f.schema, f.name)} has no fixed search_path`,
        severity: 'warning',
        file: f.loc.file,
        line: f.loc.line,
        cwe: 'CWE-426',
        object: sig,
        description:
          `${qn(f.schema, f.name)} runs with its owner's privileges but resolves table and function names through the CALLER's search_path. ` +
          'Someone who can create objects in a schema on that path (or a temporary table, which Postgres searches first) can make the function ' +
          'read or call their object instead of yours, with the owner\'s rights. Postgres and Supabase both recommend pinning search_path on every SECURITY DEFINER function.',
        recommendation: `alter function ${sig} set search_path = ''; and schema-qualify every name in the body (public.profiles, auth.uid()). If that is too much, use set search_path = public, pg_temp.`,
      });
    }

    if (isTrigger || !exposed.has(f.schema)) continue;
    const callers = ROLES.filter((r) => f.execute.has(r) || f.execute.has('public'));
    if (!callers.length) continue;
    const guarded = bodyChecksCaller(f.body);
    const hits = guarded ? [] : bodyRefs(model, f).filter((r) => r.table.rls && !r.table.forced);
    let worst: { ref: BodyRef; level: Sensitivity; reason: string } | null = null;
    for (const ref of hits) {
      const v = classifyTable(ref.table, cfg);
      if (v.level === 'public' && !ref.write) continue;
      const level: Sensitivity = v.level === 'public' ? 'unknown' : v.level;
      if (!worst || RANK[level] > RANK[worst.level] || (RANK[level] === RANK[worst.level] && ref.write && !worst.ref.write)) worst = { ref, level, reason: v.reason };
    }
    const revoke = `revoke execute on function ${sig} from public, anon${callers.includes('authenticated') ? ', authenticated' : ''};`;
    if (worst) {
      const tname = qn(worst.ref.table.schema, worst.ref.table.name);
      out.push({
        rule: 'security-definer-rls-bypass',
        title: `RPC ${qn(f.schema, f.name)} ${worst.ref.write ? 'writes' : 'reads'} ${tname} as its owner, bypassing RLS`,
        severity: worst.level === 'sensitive' ? 'critical' : 'warning',
        file: f.loc.file,
        line: f.loc.line,
        cwe: 'CWE-285',
        object: sig,
        description:
          `${who(callers)} can call ${qn(f.schema, f.name)} through the API (POST /rest/v1/rpc/${f.name}) and it ${worst.ref.write ? 'changes' : 'returns'} rows of ${tname} for everyone, not just the caller. ` +
          `The function is SECURITY DEFINER, so it runs as its owner and the Row-Level Security policies on ${tname} do not apply; its body never checks auth.uid() / auth.jwt(), ` +
          `so whatever ids the caller passes are trusted. ${worst.level === 'sensitive' ? `${tname} holds private data (${worst.reason}).` : `Review whether ${tname} is meant to be readable by everyone.`} ` +
          `EXECUTE is held by ${[...f.execute].filter((r) => r !== 'service_role').join(', ')} (Postgres grants it to PUBLIC by default and Supabase to anon and authenticated).`,
        recommendation:
          `Make it security invoker so RLS applies (alter function ${sig} security invoker;), or keep it definer and filter by the caller inside it (where user_id = (select auth.uid())). ` +
          `If only your server calls it: ${revoke} grant execute on function ${sig} to service_role;`,
      });
      continue;
    }
    const anon = callers.includes('anon');
    out.push({
      rule: 'security-definer-exposed',
      title: `SECURITY DEFINER function ${qn(f.schema, f.name)} is callable by ${callers.join(' and ')}`,
      severity: anon && !guarded ? 'warning' : 'info',
      file: f.loc.file,
      line: f.loc.line,
      cwe: 'CWE-250',
      object: sig,
      description:
        `${qn(f.schema, f.name)} is in an API-exposed schema, runs with its owner's privileges (SECURITY DEFINER) and ${who(callers)} may EXECUTE it ` +
        `via POST /rest/v1/rpc/${f.name}${guarded ? '. Its body checks the caller (auth.uid() / auth.jwt()), which is the right pattern; make sure every path does.' : ', and its body never checks who is calling.'} ` +
        'Postgres grants EXECUTE on new functions to PUBLIC and Supabase also to anon and authenticated, so revoking from PUBLIC alone is not enough.',
      recommendation: `If it is only used inside policies or by your server, move it to a schema the API does not expose (e.g. private) or ${revoke} Otherwise make it security invoker where possible.`,
    });
  }
}

// ------------------------------------------------------------------ views

function viewChecks(model: DbModel, cfg: RlsProjectConfig, exposed: Set<string>, out: DeepIssue[]): void {
  for (const v of model.views.values()) {
    if (!exposed.has(v.schema) || v.securityInvoker || v.callerScoped) continue;
    const readers = ROLES.filter((r) => v.grants.get(r)?.has('select') || v.grants.get('public')?.has('select'));
    if (!readers.length) continue;
    const protectedSources = v.sources.filter((t) => alive(model, t) && t.rls && !t.forced);
    let worst: { t: TableState; level: Sensitivity; reason: string } | null = null;
    for (const t of protectedSources) {
      const c = classifyTable(t, cfg);
      if (!worst || RANK[c.level] > RANK[worst.level]) worst = { t, level: c.level, reason: c.reason };
    }
    if (!worst || worst.level === 'public') continue;
    out.push(viewIssue(v, readers, worst));
  }
}

function viewIssue(v: ViewState, readers: Role[], worst: { t: TableState; level: Sensitivity; reason: string }): DeepIssue {
  const name = qn(v.schema, v.name);
  const tname = qn(worst.t.schema, worst.t.name);
  return {
    rule: 'view-rls-bypass',
    title: `${v.materialized ? 'Materialized view' : 'View'} ${name} exposes ${tname} without its RLS policies`,
    severity: worst.level === 'sensitive' ? 'critical' : 'warning',
    file: v.loc.file,
    line: v.loc.line,
    cwe: 'CWE-285',
    object: name,
    description:
      `${who(readers)} can read every row of ${tname} through ${name} (GET /rest/v1/${v.name}), even though ${tname} has Row-Level Security. ` +
      (v.materialized
        ? 'A materialized view stores a copy of the rows, taken as its owner, and RLS never applies to it.'
        : 'A view runs its query as the view owner (postgres), who bypasses RLS, unless it is created WITH (security_invoker = true) (Postgres 15+).') +
      ` ${worst.level === 'sensitive' ? `${tname} holds private data (${worst.reason}).` : `Review whether ${tname} is meant to be public.`} This is the final state after replaying the migrations in order.`,
    recommendation: v.materialized
      ? `Move it to a schema the API does not expose (alter materialized view ${name} set schema private;) or revoke select on ${name} from anon, authenticated; and read it from your server.`
      : `alter view ${name} set (security_invoker = true); so the caller's RLS applies (Postgres 15+), or revoke select on ${name} from anon, authenticated;`,
  };
}

// ------------------------------------------------------------------ triggers

const PRIV_TABLE_WORDS = new Set(['role', 'admin', 'permission', 'privilege', 'membership', 'staff', 'moderator', 'superuser', 'acl', 'grant', 'entitlement']);
const PRIV_COLUMN_RE = /^(?:role|roles|user_role|app_role|is_admin|admin|is_superuser|is_staff|is_moderator|permissions|access_level|claims|plan|tier)$/;
const USER_INPUT_RE = /\bnew\s*\.\s*"?(raw_user_meta_data|user_metadata|role|roles|user_role|app_role|is_admin|admin|is_superuser|is_staff|permissions|access_level|plan|tier)"?\b/i;

interface WriteStmt {
  table: string[];
  columns: string[];
  text: string;
  line: number;
}

/** INSERT / UPDATE statements in a function body, with target, columns written and text. */
function bodyWrites(f: FunctionState): WriteStmt[] {
  const out: WriteStmt[] = [];
  for (const st of splitStatements(f.body, f.bodyLine - 1)) {
    const toks = st.tokens;
    for (let k = 0; k < toks.length; k++) {
      const t = toks[k]!;
      if (t.type !== 'word') continue;
      if (t.value === 'insert' && toks[k + 1]?.value === 'into') {
        const { parts, end } = nameAt(toks, k + 2);
        if (!parts) continue;
        const cols: string[] = [];
        if (toks[end]?.type === 'punct' && toks[end]!.value === '(') {
          for (let j = end + 1; j < toks.length && !(toks[j]!.type === 'punct' && toks[j]!.value === ')'); j++) {
            const v = identValue(toks[j]);
            if (v) cols.push(v);
          }
        }
        out.push({ table: parts, columns: cols, text: st.text.slice(Math.max(0, t.start - toks[0]!.start)), line: st.line });
      } else if (t.value === 'update' && !(toks[k - 1]?.type === 'word' && (toks[k - 1]!.value === 'do' || toks[k - 1]!.value === 'for'))) {
        const { parts, end } = nameAt(toks, k + 1);
        if (!parts || toks[end]?.value !== 'set') continue;
        const cols: string[] = [];
        for (let j = end + 1; j < toks.length; j++) {
          const v = identValue(toks[j]);
          if (v && toks[j + 1]?.type === 'op' && toks[j + 1]!.value === '=') cols.push(v);
          if (toks[j]!.type === 'word' && toks[j]!.value === 'where') break;
        }
        out.push({ table: parts, columns: cols, text: st.text.slice(Math.max(0, t.start - toks[0]!.start)), line: st.line });
      }
    }
  }
  return out;
}

function nameAt(toks: Token[], k: number): { parts: string[] | null; end: number } {
  const first = identValue(toks[k]);
  if (!first) return { parts: null, end: k };
  const parts = [first];
  let j = k + 1;
  while (toks[j]?.type === 'punct' && toks[j]!.value === '.' && identValue(toks[j + 1])) {
    parts.push(identValue(toks[j + 1])!);
    j += 2;
  }
  return { parts, end: j };
}

function userCanWrite(t: TableState, events: string[]): Role[] {
  const out: Role[] = [];
  for (const role of ROLES) {
    const ok = events.some((ev) => {
      if (ev !== 'insert' && ev !== 'update') return false;
      if (!hasPrivilege(t, role, ev)) return false;
      if (!t.rls) return true;
      return [...t.policies.values()].some((p: PolicyState) => p.permissive && appliesTo(p, role) && coversCommand(p, ev));
    });
    if (ok) out.push(role);
  }
  return out;
}

function triggerChecks(model: DbModel, exposed: Set<string>, out: DeepIssue[]): void {
  for (const t of model.tables.values()) {
    for (const tr of t.triggers.values()) {
      const f = triggerFunction(model, tr);
      if (!f || !f.securityDefiner) continue;
      const signup = t.schema === 'auth' && t.name === 'users' && tr.events.some((e) => e === 'insert' || e === 'update');
      const writers = signup ? (['anon'] as Role[]) : exposed.has(t.schema) ? userCanWrite(t, tr.events) : [];
      if (!writers.length) continue;
      for (const w of bodyWrites(f)) {
        const target = w.table[w.table.length - 1]!;
        const privTable = words(target).some((x) => PRIV_TABLE_WORDS.has(x));
        const privCols = w.columns.filter((c) => PRIV_COLUMN_RE.test(c.toLowerCase()));
        if (!privTable && !privCols.length) continue;
        const m = USER_INPUT_RE.exec(w.text);
        if (!m) continue;
        const src = `new.${m[1]!.toLowerCase()}`;
        const tname = qn(t.schema, t.name);
        out.push({
          rule: 'trigger-privilege-escalation',
          title: `Trigger ${tr.name} on ${tname} lets users choose their own role (${w.table.join('.')})`,
          severity: 'critical',
          file: tr.loc.file,
          line: tr.loc.line,
          cwe: 'CWE-269',
          object: `trigger ${tr.name} -> ${qn(f.schema, f.name)}`,
          description:
            `${signup ? 'Anyone who signs up' : who(writers)} can make themselves an admin: trigger ${tr.name} runs ${qn(f.schema, f.name)} on every ${tr.events.join('/').toUpperCase()} of ${tname}, ` +
            `and that SECURITY DEFINER function writes ${src} into ${w.table.join('.')}${privCols.length ? ` (${privCols.join(', ')})` : ''} with its owner's privileges, so RLS on that table does not stop it. ` +
            (signup
              ? `${src} comes from the sign-up request (supabase.auth.signUp({ options: { data: { role: 'admin' } } }) sets raw_user_meta_data), so the caller picks the value.`
              : `${src} is a column the caller writes in the same request.`) +
            ` (function at ${f.loc.file}:${f.loc.line})`,
          recommendation:
            "Never take a role from user-controlled input. Insert a fixed default (e.g. insert into public.user_roles (user_id, role) values (new.id, 'user');) and grant elevated roles only from server code using the service role, " +
            'or read them from new.raw_app_meta_data, which only the service role can set. Also pin the function: set search_path = \'\'.',
        });
        break;
      }
    }
  }
}

// ------------------------------------------------------------------ realtime

function realtimeChecks(model: DbModel, cfg: RlsProjectConfig, exposed: Set<string>, out: DeepIssue[]): void {
  const pub = model.publications.get('supabase_realtime');
  if (!pub) return;
  const members = new Map<TableState, { file: string; line: number }>();
  for (const [t, loc] of pub.tables) if (alive(model, t)) members.set(t, loc);
  if (pub.allTables || pub.schemas.size) {
    for (const t of model.tables.values()) if (!t.stub && (pub.allTables || pub.schemas.has(t.schema)) && !members.has(t)) members.set(t, pub.loc);
  }
  for (const [t, loc] of members) {
    if (!exposed.has(t.schema)) continue;
    const v = classifyTable(t, cfg);
    if (v.level === 'public') continue;
    let why: string | null = null;
    let roles: Role[] = [];
    if (!t.rls) {
      if (t.rlsUncertain) continue;
      why = 'it has no Row-Level Security';
      roles = ROLES.filter((r) => hasPrivilege(t, r, 'select'));
    } else {
      const open = openings(model, t).filter((o) => o.cmd === 'select');
      if (open.length) {
        roles = [...new Set(open.map((o) => o.role))];
        why = `its SELECT policy "${open[0]!.policy.name}" is true for every row (${open[0]!.why})`;
      }
    }
    if (!why || !roles.length) continue;
    const name = qn(t.schema, t.name);
    out.push({
      rule: 'realtime-table-exposed',
      title: `Realtime broadcasts every change to ${name} to ${roles.join(' and ')}`,
      severity: v.level === 'sensitive' ? 'critical' : 'warning',
      file: loc.file,
      line: loc.line,
      cwe: 'CWE-200',
      object: name,
      description:
        `${who(roles)} can subscribe to ${name} (supabase.channel(...).on('postgres_changes', { table: '${t.name}' })) and receive every insert and update as it happens, for all users. ` +
        `The table is in the supabase_realtime publication and ${why}; Realtime only filters changes through the subscriber's SELECT policies. ` +
        `${v.level === 'sensitive' ? `${name} holds private data (${v.reason}).` : `Review whether ${name} is meant to be public.`}`,
      recommendation:
        `Give the table an owner-scoped SELECT policy (alter table ${name} enable row level security; create policy "owners read" on ${name} for select to authenticated using ((select auth.uid()) = user_id);), ` +
        `or take it out of Realtime: alter publication supabase_realtime drop table ${name}; and use private Broadcast channels instead.`,
    });
  }
}

// ------------------------------------------------------------------ grants

const WRITE_PRIVS = new Set(['insert', 'update', 'delete', 'truncate']);

function grantChecks(model: DbModel, cfg: RlsProjectConfig, exposed: Set<string>, out: DeepIssue[]): void {
  for (const g of model.grantStatements) {
    const roles = g.roles.filter((r) => r === 'anon' || r === 'public');
    if (!roles.length) continue;
    const writes = g.objects === 'functions' ? g.privs : g.privs.filter((p) => WRITE_PRIVS.has(p));
    if (!writes.length) continue;
    if (g.kind === 'default') {
      // Supabase itself sets these defaults in `public`; repeating them changes nothing.
      const schemas = g.schemas.filter((s) => s !== 'public');
      if (!schemas.length) continue;
      const wide = schemas.includes('*');
      const exposedHit = schemas.filter((s) => exposed.has(s));
      const where = wide ? 'every schema, including private ones' : `schema ${schemas.join(', ')}`;
      out.push({
        rule: 'grant-default-privileges-anon',
        title: `Default privileges give anon ${writes.join('/').toUpperCase()} on every future ${g.objects === 'functions' ? 'function' : 'table'} in ${wide ? 'every schema' : schemas.join(', ')}`,
        severity: wide || exposedHit.length ? 'warning' : 'info',
        file: g.loc.file,
        line: g.loc.line,
        cwe: 'CWE-276',
        object: `default privileges (${where})`,
        description:
          `Every ${g.objects === 'functions' ? 'function' : 'table'} created later in ${where} will automatically be ${g.objects === 'functions' ? 'callable' : 'writable'} by ${roles.includes('public') ? 'every role, including anon' : 'anon'} (no sign-in needed). ` +
          `Nothing protects a new ${g.objects === 'functions' ? 'function' : 'table'} until someone remembers to ${g.objects === 'functions' ? 'revoke EXECUTE' : 'enable RLS'} on it; ` +
          `${exposedHit.length || wide ? 'the schema is served by the Data API.' : 'the schema is not exposed by the Data API today, but would be the moment it is added to [api] schemas.'}`,
        recommendation: `Grant per object instead and remove the default: alter default privileges ${wide ? '' : `in schema ${schemas.join(', ')} `}revoke ${writes.join(', ')} on ${g.objects} from ${roles.join(', ')};`,
      });
      continue;
    }
    // GRANT ... ON ALL TABLES IN SCHEMA s TO anon, on tables that had been locked down earlier, or outside `public`.
    const schemas = g.schemas.filter((s) => exposed.has(s) && s !== 'public');
    const relocked = g.relocked.filter((t) => alive(model, t) && exposed.has(t.schema));
    if (!schemas.length && !relocked.length) continue;
    const target = relocked.length ? relocked.map((t) => qn(t.schema, t.name)).slice(0, 5).join(', ') : `every table in ${schemas.join(', ')}`;
    out.push({
      rule: 'grant-all-tables-anon',
      title: `Blanket GRANT gives anon ${writes.join('/').toUpperCase()} on ${relocked.length ? 'tables that were locked down' : `every table in ${schemas.join(', ')}`}`,
      severity: 'warning',
      file: g.loc.file,
      line: g.loc.line,
      cwe: 'CWE-276',
      object: `grant on all tables in schema ${g.schemas.join(', ')}`,
      description:
        `This GRANT ... ON ALL TABLES IN SCHEMA ${g.schemas.join(', ')} TO ${roles.join(', ')} hands anon (no sign-in) ${writes.join(', ')} on ${target}. ` +
        (relocked.length
          ? 'An earlier migration had revoked anon\'s privileges on these tables on purpose; this statement silently undoes that.'
          : 'Only RLS now stands between anon and every row of those tables; one table without a policy is fully writable.'),
      recommendation: `Grant only what each table needs, to the role that needs it, e.g. grant select on public.<table> to anon; grant insert, update on public.<table> to authenticated; and revoke the rest: revoke ${writes.join(', ')} on all tables in schema ${g.schemas.join(', ')} from anon;`,
    });
  }

  for (const t of model.tables.values()) {
    if (!exposed.has(t.schema) || !t.columnGrants.length) continue;
    const opened = t.rls ? openings({ ...model }, { ...t, grants: withColumnSelect(t) }) : [];
    for (const role of ROLES) {
      const canReadRows = !t.rls || opened.some((o) => o.role === role && o.cmd === 'select');
      if (!canReadRows) continue;
      const grants = t.columnGrants.filter((g) => (g.role === role || g.role === 'public') && g.priv === 'select');
      for (const g of grants) {
        const cols = g.columns.map((c) => ({ c, s: columnSensitivity(c) })).filter((x) => x.s);
        if (!cols.length) continue;
        const secret = cols.some((x) => x.s === 'secret');
        const name = qn(t.schema, t.name);
        out.push({
          rule: 'grant-sensitive-column',
          title: `${role} can read ${cols.map((x) => x.c).join(', ')} of every row in ${name}`,
          severity: secret || role === 'anon' ? 'critical' : 'warning',
          file: g.loc.file,
          line: g.loc.line,
          cwe: secret ? 'CWE-522' : 'CWE-359',
          object: `${name} (${cols.map((x) => x.c).join(', ')})`,
          description:
            `${who([role])} can read ${cols.map((x) => `${x.c} (${x.s === 'secret' ? 'a credential' : 'personal data'})`).join(', ')} for all users: ` +
            `this column-level GRANT SELECT includes ${cols.length > 1 ? 'them' : 'it'}, and ${t.rls ? 'a SELECT policy on the table is true for every row' : 'the table has no Row-Level Security'}. ` +
            'Column grants are how Supabase projects hide columns, so a sensitive column in the list defeats the point.',
          recommendation: `revoke select (${cols.map((x) => x.c).join(', ')}) on ${name} from ${role}; and grant only the columns the client needs, or move the private columns to a separate table with an owner-only policy.`,
        });
      }
    }
  }
}

/** The table as if column-level SELECT grants were table-level (to ask whether a role can read rows at all). */
function withColumnSelect(t: TableState): TableState['grants'] {
  const g = new Map([...t.grants].map(([k, v]) => [k, new Set(v)]));
  for (const cg of t.columnGrants) {
    if (cg.priv !== 'select') continue;
    const set = g.get(cg.role) ?? new Set();
    set.add('select');
    g.set(cg.role, set);
  }
  return g;
}

// ------------------------------------------------------------------ entry

export function analyzeSupabaseObjects(model: DbModel, opts: DeepOptions = {}): DeepIssue[] {
  const cfg = opts.config ?? {};
  if (!opts.supabase && !model.rlsUsed) return [];
  const exposed = exposedSet(cfg);
  const out: DeepIssue[] = [];
  const steps: [string, () => void][] = [
    ['storage', () => storageChecks(model, cfg, out)],
    ['functions', () => functionChecks(model, cfg, exposed, out)],
    ['views', () => viewChecks(model, cfg, exposed, out)],
    ['triggers', () => triggerChecks(model, exposed, out)],
    ['realtime', () => realtimeChecks(model, cfg, exposed, out)],
    ['grants', () => grantChecks(model, cfg, exposed, out)],
  ];
  for (const [, run] of steps) run();
  return out.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.rule.localeCompare(b.rule));
}
