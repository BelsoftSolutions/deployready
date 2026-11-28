/**
 * Migration-aware model of a Postgres schema's access-control state.
 *
 * `replayMigrations` applies SQL files in migration order and reconstructs the FINAL state of
 * every table: schema + name (after RENAME / SET SCHEMA / ALTER SCHEMA RENAME), kind (unlogged,
 * partitioned, partition), columns, RLS enabled / forced, policies (permissive or restrictive,
 * command, roles, USING, WITH CHECK, after CREATE / ALTER / DROP POLICY) and table privileges of
 * anon / authenticated (Supabase's default grants in `public`, GRANT / REVOKE, ALTER DEFAULT
 * PRIVILEGES). DROP TABLE forgets everything about a table; re-creating it starts from scratch.
 *
 * Statements we do not understand are skipped. Plain statements inside DO blocks (e.g. idempotent
 * `if not exists (...) then create policy ... end if`) and `execute '<literal sql>'` are applied;
 * dynamic `execute format(... enable row level security ...)` marks the tables that existed at
 * that point as "RLS state uncertain", so they are never reported as missing RLS.
 */
import { splitStatements, type Statement, type Token } from './lexer';
import { identValue, parseExpr, type Expr } from './expr';

export interface SqlSource {
  relPath: string;
  source: string;
}

export interface Loc {
  file: string;
  line: number;
}

export type PolicyCommand = 'all' | 'select' | 'insert' | 'update' | 'delete';
export type Privilege = 'select' | 'insert' | 'update' | 'delete' | 'truncate' | 'references' | 'trigger';
const ALL_PRIVS: Privilege[] = ['select', 'insert', 'update', 'delete', 'truncate', 'references', 'trigger'];

export interface PolicyState {
  name: string;
  permissive: boolean;
  command: PolicyCommand;
  /** Lower-cased role names; `public` means every role. */
  roles: string[];
  using: Expr | null;
  check: Expr | null;
  hasUsing: boolean;
  hasCheck: boolean;
  usingText: string;
  checkText: string;
  /** Where the policy got its current definition (CREATE or the last ALTER that changed it). */
  loc: Loc;
}

export type TableKind = 'table' | 'unlogged' | 'partitioned' | 'partition';

export interface TableState {
  schema: string;
  name: string;
  kind: TableKind;
  /** Known column names; null when unknown (CREATE TABLE AS, stub). */
  columns: Set<string> | null;
  rls: boolean;
  forced: boolean;
  /** RLS may have been enabled by dynamic SQL we could not resolve. */
  rlsUncertain: boolean;
  /** Not created in the SQL we saw (e.g. made in the dashboard); only referenced. */
  stub: boolean;
  /** Set when an explicit DISABLE ROW LEVEL SECURITY is the final word on RLS. */
  disabledAt?: Loc;
  /** Where the table got its current schema + name (CREATE, RENAME, SET SCHEMA). */
  loc: Loc;
  policies: Map<string, PolicyState>;
  grants: Map<string, Set<Privilege>>;
  /** Column-level grants (`GRANT SELECT (a, b) ON t TO r`), in statement order. */
  columnGrants: ColumnGrant[];
  /** Triggers on this table (they move with RENAME / SET SCHEMA and go away with DROP TABLE). */
  triggers: Map<string, TriggerState>;
  /** A table-level REVOKE ... FROM anon (or PUBLIC) was applied: the table was locked down on purpose. */
  anonRevokedAt?: Loc;
  parent?: string;
}

export interface ColumnGrant {
  role: string;
  priv: Privilege;
  columns: string[];
  loc: Loc;
}

export interface TriggerState {
  name: string;
  /** before / after / instead of */
  timing: string;
  /** insert / update / delete / truncate */
  events: string[];
  /** The trigger function as written (unqualified names resolve through `fnPath`). */
  fnParts: string[];
  fnPath: string[];
  loc: Loc;
}

export interface FunctionState {
  schema: string;
  name: string;
  kind: 'function' | 'procedure';
  /** Argument list as written (normalised whitespace). */
  args: string;
  /** Return type as written, lower-cased (`trigger`, `setof invoices`, `void`, ...). */
  returns: string;
  language: string;
  securityDefiner: boolean;
  /** Value of `SET search_path` on the function, or null when it has none. */
  searchPath: string | null;
  body: string;
  /** 1-based line of the body's first character. */
  bodyLine: number;
  loc: Loc;
  /** search_path when the function was created: how unqualified names in its body resolve without SET search_path. */
  createPath: string[];
  /** Roles holding EXECUTE (`public` = every role). */
  execute: Set<string>;
}

export interface ViewState {
  schema: string;
  name: string;
  materialized: boolean;
  /** `WITH (security_invoker = true)` (PG15+): the view checks the caller's RLS instead of the owner's. */
  securityInvoker: boolean;
  /** Tables the view reads (as resolved when it was created). */
  sources: TableState[];
  /** The defining query filters by the caller (auth.uid() / auth.jwt() / current_user). */
  callerScoped: boolean;
  loc: Loc;
  grants: Map<string, Set<Privilege>>;
}

export interface BucketState {
  id: string;
  public: boolean;
  /** Where the bucket got its current `public` value. */
  loc: Loc;
}

export interface PublicationState {
  name: string;
  allTables: boolean;
  schemas: Set<string>;
  tables: Map<TableState, Loc>;
  loc: Loc;
}

/** A blanket privilege statement worth reporting on its own (default privileges, ALL TABLES IN SCHEMA). */
export interface GrantStatement {
  kind: 'default' | 'all-tables';
  /** `*` = every schema (ALTER DEFAULT PRIVILEGES without IN SCHEMA). */
  schemas: string[];
  roles: string[];
  privs: string[];
  /** tables / functions / sequences / types */
  objects: string;
  loc: Loc;
  /** For `all-tables`: the tables it applied to at that point. */
  tables: TableState[];
  /** For `all-tables`: those of `tables` an earlier REVOKE had locked down for anon. */
  relocked: TableState[];
}

export interface DbModel {
  tables: Map<string, TableState>;
  /** True when any statement enabled RLS on any table (the project uses RLS). */
  rlsUsed: boolean;
  functions: Map<string, FunctionState>;
  views: Map<string, ViewState>;
  /** storage.buckets rows inserted / updated by the SQL (key: bucket id). */
  buckets: Map<string, BucketState>;
  publications: Map<string, PublicationState>;
  grantStatements: GrantStatement[];
}

export const tableKey = (schema: string, name: string): string => `${schema}\u0000${name}`;

const MIGRATION_DIR_RE = /(^|\/)migrations?\//i;

/**
 * Migration order: files under a `migrations/` directory first (Supabase timestamps, Prisma /
 * numbered folders: natural sort by path), then every other .sql file (schema dumps, seeds).
 */
export function orderSqlFiles<T extends SqlSource>(files: T[]): T[] {
  const rank = (f: T): number => (MIGRATION_DIR_RE.test(f.relPath) ? 0 : 1);
  return [...files].sort((a, b) => rank(a) - rank(b) || a.relPath.localeCompare(b.relPath, 'en', { numeric: true }));
}

/** Supabase grants these on every table created in `public` (via default privileges). */
function initialDefaults(): Map<string, Set<Privilege>> {
  const m = new Map<string, Set<Privilege>>();
  for (const role of ['anon', 'authenticated', 'service_role']) m.set(`public\u0000${role}`, new Set(ALL_PRIVS));
  return m;
}

/**
 * EXECUTE on new functions: Postgres grants it to PUBLIC everywhere (`*`), and Supabase's default
 * privileges also grant it to anon, authenticated and service_role in `public`. Revoking from
 * PUBLIC alone therefore still leaves anon able to call a function in `public`.
 */
function initialFnDefaults(): Map<string, boolean> {
  const m = new Map<string, boolean>();
  m.set('*\u0000public', true);
  for (const role of ['anon', 'authenticated', 'service_role']) m.set(`public\u0000${role}`, true);
  return m;
}

export const fnKey = (schema: string, name: string): string => `${schema}\u0000${name}`;

class Cursor {
  i = 0;
  constructor(readonly t: Token[]) {}
  peek(o = 0): Token | undefined {
    return this.t[this.i + o];
  }
  word(o = 0): string | null {
    const t = this.peek(o);
    return t?.type === 'word' ? t.value : null;
  }
  is(...words: string[]): boolean {
    return words.every((w, k) => this.word(k) === w);
  }
  eat(...words: string[]): boolean {
    if (!this.is(...words)) return false;
    this.i += words.length;
    return true;
  }
  punct(v: string, o = 0): boolean {
    const t = this.peek(o);
    return t?.type === 'punct' && t.value === v;
  }
  done(): boolean {
    return this.i >= this.t.length;
  }
  /** A possibly qualified name: [schema.]name (identifiers normalised). */
  name(): string[] | null {
    const first = identValue(this.peek());
    if (!first) return null;
    const parts = [first];
    this.i++;
    while (this.punct('.') && identValue(this.peek(1))) {
      parts.push(identValue(this.peek(1))!);
      this.i += 2;
    }
    return parts;
  }
  /** Tokens inside the parenthesis group that starts here; cursor moves past it. */
  group(): Token[] | null {
    if (!this.punct('(')) return null;
    let depth = 0;
    const start = this.i;
    do {
      const t = this.peek();
      if (!t) return null;
      if (t.type === 'punct' && t.value === '(') depth++;
      else if (t.type === 'punct' && t.value === ')') depth--;
      this.i++;
    } while (depth > 0);
    return this.t.slice(start + 1, this.i - 1);
  }
  /** Split the remaining tokens at top-level commas. */
  restByComma(): Token[][] {
    const out: Token[][] = [];
    let cur: Token[] = [];
    let depth = 0;
    for (; this.i < this.t.length; this.i++) {
      const t = this.t[this.i]!;
      if (t.type === 'punct' && t.value === '(') depth++;
      if (t.type === 'punct' && t.value === ')') depth--;
      if (depth === 0 && t.type === 'punct' && t.value === ',') {
        out.push(cur);
        cur = [];
        continue;
      }
      cur.push(t);
    }
    if (cur.length) out.push(cur);
    return out;
  }
}

function splitByComma(tokens: Token[]): Token[][] {
  return new Cursor(tokens).restByComma();
}

const COLUMN_CONSTRAINT_STARTS = new Set(['constraint', 'primary', 'unique', 'check', 'foreign', 'exclude', 'like']);

function textOf(tokens: Token[], src: string): string {
  if (tokens.length === 0) return '';
  return src.slice(tokens[0]!.start, tokens[tokens.length - 1]!.end).replace(/\s+/g, ' ').trim();
}

class Replayer {
  readonly tables = new Map<string, TableState>();
  readonly functions = new Map<string, FunctionState>();
  readonly views = new Map<string, ViewState>();
  readonly buckets = new Map<string, BucketState>();
  readonly publications = new Map<string, PublicationState>();
  readonly grantStatements: GrantStatement[] = [];
  rlsUsed = false;
  private defaults = initialDefaults();
  private fnDefaults = initialFnDefaults();
  private searchPath: string[] = ['public'];
  private file = '';
  private src = '';

  run(files: SqlSource[]): DbModel {
    for (const f of orderSqlFiles(files)) {
      this.file = f.relPath;
      this.searchPath = ['public']; // each migration file runs in a fresh session
      this.runSource(f.source, 0);
    }
    return {
      tables: this.tables,
      rlsUsed: this.rlsUsed,
      functions: this.functions,
      views: this.views,
      buckets: this.buckets,
      publications: this.publications,
      grantStatements: this.grantStatements,
    };
  }

  private runSource(source: string, lineBase: number, depth = 0): void {
    const prevSrc = this.src;
    this.src = source;
    for (const st of splitStatements(source, lineBase)) {
      try {
        this.statement(st, depth);
      } catch {
        // tolerant: an odd statement never stops the replay
      }
    }
    this.src = prevSrc;
  }

  private loc(st: Statement): Loc {
    return { file: this.file, line: st.line };
  }

  // ------------------------------------------------------------ names

  private creationSchema(): string {
    return this.searchPath.find((s) => s !== '$user' && s !== 'pg_temp' && s !== 'pg_catalog') ?? 'public';
  }

  private resolve(parts: string[]): { schema: string; name: string } {
    if (parts.length >= 2) return { schema: parts[parts.length - 2]!, name: parts[parts.length - 1]! };
    const name = parts[0]!;
    for (const s of this.searchPath) if (this.tables.has(tableKey(s, name))) return { schema: s, name };
    return { schema: this.creationSchema(), name };
  }

  private lookup(parts: string[]): TableState | undefined {
    const { schema, name } = this.resolve(parts);
    return this.tables.get(tableKey(schema, name));
  }

  /** The table, or a stub for one created outside the SQL we saw. */
  private lookupOrStub(parts: string[], st: Statement): TableState {
    const hit = this.lookup(parts);
    if (hit) return hit;
    const { schema, name } = this.resolve(parts);
    const t = this.newTable(schema, name, 'table', null, this.loc(st));
    t.stub = true;
    return t;
  }

  private newTable(schema: string, name: string, kind: TableKind, columns: Set<string> | null, loc: Loc): TableState {
    const grants = this.defaultGrants(schema);
    const t: TableState = {
      schema,
      name,
      kind,
      columns,
      rls: false,
      forced: false,
      rlsUncertain: false,
      stub: false,
      loc,
      policies: new Map(),
      grants,
      columnGrants: [],
      triggers: new Map(),
    };
    this.tables.set(tableKey(schema, name), t);
    return t;
  }

  /** Default table grants for a new relation (table or view) in `schema`. */
  private defaultGrants(schema: string): Map<string, Set<Privilege>> {
    const grants = new Map<string, Set<Privilege>>();
    for (const [k, privs] of this.defaults) {
      const [s, role] = k.split('\u0000') as [string, string];
      if (s === schema || s === '*') {
        const g = grants.get(role) ?? new Set<Privilege>();
        privs.forEach((p) => g.add(p));
        grants.set(role, g);
      }
    }
    return grants;
  }

  private defaultExecute(schema: string): Set<string> {
    const out = new Set<string>();
    for (const [k, on] of this.fnDefaults) {
      const [s, role] = k.split('\u0000') as [string, string];
      if (on && (s === schema || s === '*')) out.add(role);
    }
    // A per-schema REVOKE cannot take back a global grant, but a global REVOKE ... FROM PUBLIC does.
    return out;
  }

  private resolveFn(parts: string[], path: string[] = this.searchPath): { schema: string; name: string } {
    if (parts.length >= 2) return { schema: parts[parts.length - 2]!, name: parts[parts.length - 1]! };
    const name = parts[0]!;
    for (const s of path) if (this.functions.has(fnKey(s, name))) return { schema: s, name };
    return { schema: path.find((s) => s !== '$user' && s !== 'pg_temp' && s !== 'pg_catalog') ?? 'public', name };
  }

  private resolveView(parts: string[]): ViewState | undefined {
    if (parts.length >= 2) return this.views.get(tableKey(parts[parts.length - 2]!, parts[parts.length - 1]!));
    for (const s of this.searchPath) {
      const v = this.views.get(tableKey(s, parts[0]!));
      if (v) return v;
    }
    return undefined;
  }

  private move(t: TableState, schema: string, name: string, loc: Loc): void {
    this.tables.delete(tableKey(t.schema, t.name));
    t.schema = schema;
    t.name = name;
    t.loc = loc;
    this.tables.set(tableKey(schema, name), t);
  }

  // ------------------------------------------------------------ dispatch

  private statement(st: Statement, depth: number): void {
    const c = new Cursor(st.tokens);
    const w0 = c.word();
    if (!w0) {
      // a bare dollar-quoted block cannot be a statement; ignore
      return;
    }
    if (w0 === 'create') return this.create(c, st);
    if (w0 === 'alter') return this.alter(c, st);
    if (w0 === 'drop') return this.drop(c, st);
    if (w0 === 'grant') return this.grantRevoke(c, st, true);
    if (w0 === 'revoke') return this.grantRevoke(c, st, false);
    if (w0 === 'set' || w0 === 'reset') return this.setPath(c);
    if (w0 === 'select') return this.selectSetConfig(st);
    if (w0 === 'do' && depth < 3) return this.doBlock(c, st, depth);
    if (w0 === 'insert') return this.insertBuckets(c, st);
    if (w0 === 'update') return this.updateBuckets(c, st);
    if (w0 === 'delete') return this.deleteBuckets(c);
  }

  // ------------------------------------------------------------ CREATE

  private create(c: Cursor, st: Statement): void {
    c.i++;
    const orReplace = c.eat('or', 'replace');
    if (c.word() === 'policy') return this.createPolicy(c, st);
    if (c.word() === 'schema') return;
    if (c.word() === 'function' || c.word() === 'procedure') return this.createFunction(c, st, orReplace);
    if (c.word() === 'trigger' || c.is('constraint', 'trigger')) return this.createTrigger(c, st);
    if (c.word() === 'publication') return this.createPublication(c, st);
    if (c.word() === 'view' || c.is('recursive', 'view') || c.is('materialized', 'view')) return this.createView(c, st);
    if ((c.word() === 'temp' || c.word() === 'temporary') && (c.word(1) === 'view' || c.is(c.word()!, 'recursive', 'view'))) return; // session-local
    let kind: TableKind = 'table';
    let temp = false;
    for (;;) {
      const w = c.word();
      if (w === 'global' || w === 'local') c.i++;
      else if (w === 'temp' || w === 'temporary') {
        temp = true;
        c.i++;
      } else if (w === 'unlogged') {
        kind = 'unlogged';
        c.i++;
      } else break;
    }
    if (c.word() !== 'table') return;
    c.i++;
    // Temporary tables live in the creating session only: never API-exposed.
    if (temp) return;
    const ifNotExists = c.eat('if', 'not', 'exists');
    const parts = c.name();
    if (!parts) return;
    const { schema, name } = this.resolve(parts);
    const existing = this.tables.get(tableKey(schema, name));
    if (existing && !existing.stub) {
      // IF NOT EXISTS is a no-op; a plain CREATE of an existing table fails in Postgres.
      void ifNotExists;
      return;
    }
    const loc = this.loc(st);
    let columns: Set<string> | null = new Set<string>();
    let parent: TableState | undefined;
    if (c.eat('partition', 'of')) {
      const pp = c.name();
      parent = pp ? this.lookup(pp) : undefined;
      columns = parent?.columns ? new Set(parent.columns) : null;
      kind = 'partition';
    } else if (c.word() === 'of') {
      columns = null;
    } else if (c.punct('(')) {
      const body = c.group() ?? [];
      for (const el of splitByComma(body)) {
        const first = el[0];
        const v = identValue(first);
        if (!v) continue;
        if (first!.type === 'word' && v === 'like') {
          const like = new Cursor(el.slice(1)).name();
          const src = like ? this.lookup(like) : undefined;
          if (src?.columns) src.columns.forEach((x) => columns!.add(x));
          else columns = null;
          continue;
        }
        if (first!.type === 'word' && COLUMN_CONSTRAINT_STARTS.has(v)) continue;
        columns?.add(v);
      }
      if (c.eat('partition', 'by')) kind = kind === 'unlogged' ? 'unlogged' : 'partitioned';
    } else {
      columns = null; // CREATE TABLE ... AS
    }
    const t = existing ?? this.newTable(schema, name, kind, columns, loc);
    if (existing) {
      // a stub referenced earlier (policy / grant) is now really created: keep what was applied to it
      existing.stub = false;
      existing.kind = kind;
      existing.columns = columns;
      existing.loc = loc;
    }
    if (parent) t.parent = tableKey(parent.schema, parent.name);
  }

  private createPolicy(c: Cursor, st: Statement): void {
    c.i++; // policy
    const name = identValue(c.peek());
    if (!name) return;
    c.i++;
    if (!c.eat('on')) return;
    const parts = c.name();
    if (!parts) return;
    const t = this.lookupOrStub(parts, st);
    const p: PolicyState = {
      name,
      permissive: true,
      command: 'all',
      roles: ['public'],
      using: null,
      check: null,
      hasUsing: false,
      hasCheck: false,
      usingText: '',
      checkText: '',
      loc: this.loc(st),
    };
    if (c.eat('as')) {
      if (c.eat('restrictive')) p.permissive = false;
      else c.eat('permissive');
    }
    if (c.eat('for')) {
      const cmd = c.word();
      if (cmd === 'all' || cmd === 'select' || cmd === 'insert' || cmd === 'update' || cmd === 'delete') p.command = cmd;
      c.i++;
    }
    this.policyClauses(c, p);
    t.policies.set(name, p);
  }

  /** `[TO roles] [USING (...)] [WITH CHECK (...)]`, shared by CREATE and ALTER POLICY. */
  private policyClauses(c: Cursor, p: PolicyState): void {
    while (!c.done()) {
      if (c.eat('to')) {
        const roles: string[] = [];
        for (;;) {
          const r = identValue(c.peek());
          if (!r) break;
          roles.push(r === 'current_user' || r === 'session_user' || r === 'current_role' ? 'postgres' : r);
          c.i++;
          if (c.punct(',')) {
            c.i++;
            continue;
          }
          break;
        }
        if (roles.length) p.roles = roles;
        continue;
      }
      if (c.eat('using')) {
        const g = c.group();
        if (!g) return;
        p.hasUsing = true;
        p.using = parseExpr(g);
        p.usingText = textOf(g, this.src);
        continue;
      }
      if (c.eat('with', 'check')) {
        const g = c.group();
        if (!g) return;
        p.hasCheck = true;
        p.check = parseExpr(g);
        p.checkText = textOf(g, this.src);
        continue;
      }
      c.i++;
    }
  }

  // ------------------------------------------------------------ ALTER

  private alter(c: Cursor, st: Statement): void {
    c.i++;
    const what = c.word();
    if (what === 'policy') return this.alterPolicy(c, st);
    if (what === 'schema') return this.alterSchema(c, st);
    if (what === 'default') return this.alterDefaultPrivileges(c, st);
    if (what === 'function' || what === 'procedure' || what === 'routine') return this.alterFunction(c, st);
    if (what === 'view' || (what === 'materialized' && c.word(1) === 'view')) return this.alterView(c, st);
    if (what === 'publication') return this.alterPublication(c, st);
    if (what !== 'table') return;
    c.i++;
    if (c.word() === 'all') return; // ALTER TABLE ALL IN TABLESPACE
    c.eat('if', 'exists');
    c.eat('only');
    const parts = c.name();
    if (!parts) return;
    if (c.peek()?.type === 'op' && c.peek()!.value === '*') c.i++;
    const loc = this.loc(st);
    // RENAME / SET SCHEMA are single-action forms
    if (c.is('rename', 'to')) {
      c.i += 2;
      const nn = identValue(c.peek());
      const t = this.lookup(parts);
      if (nn && t) this.move(t, t.schema, nn, loc);
      return;
    }
    if (c.eat('rename')) {
      if (c.word() === 'constraint') return;
      c.eat('column');
      const from = identValue(c.peek());
      c.i++;
      if (!c.eat('to')) return;
      const to = identValue(c.peek());
      const t = this.lookup(parts);
      if (t?.columns && from && to && t.columns.delete(from)) t.columns.add(to);
      return;
    }
    if (c.is('set', 'schema')) {
      c.i += 2;
      const ns = identValue(c.peek());
      const t = this.lookup(parts);
      if (ns && t) this.move(t, ns, t.name, loc);
      return;
    }
    const t = this.lookupOrStub(parts, st);
    for (const action of c.restByComma()) this.tableAction(t, new Cursor(action), loc);
  }

  private tableAction(t: TableState, a: Cursor, loc: Loc): void {
    if (a.eat('enable', 'row', 'level', 'security')) {
      t.rls = true;
      t.disabledAt = undefined;
      this.rlsUsed = true;
      return;
    }
    if (a.eat('disable', 'row', 'level', 'security')) {
      if (t.rls || t.stub || !t.disabledAt) t.disabledAt = loc;
      t.rls = false;
      t.rlsUncertain = false;
      return;
    }
    if (a.eat('force', 'row', 'level', 'security')) {
      t.forced = true;
      return;
    }
    if (a.eat('no', 'force', 'row', 'level', 'security')) {
      t.forced = false;
      return;
    }
    if (a.eat('add')) {
      if (a.word() !== null && COLUMN_CONSTRAINT_STARTS.has(a.word()!)) return;
      a.eat('column');
      a.eat('if', 'not', 'exists');
      const col = identValue(a.peek());
      if (col && t.columns) t.columns.add(col);
      return;
    }
    if (a.eat('drop')) {
      if (a.word() === 'constraint') return;
      a.eat('column');
      a.eat('if', 'exists');
      const col = identValue(a.peek());
      if (col && t.columns) t.columns.delete(col);
      return;
    }
  }

  private alterPolicy(c: Cursor, st: Statement): void {
    c.i++;
    const name = identValue(c.peek());
    if (!name) return;
    c.i++;
    if (!c.eat('on')) return;
    const parts = c.name();
    if (!parts) return;
    const t = this.lookup(parts);
    const p = t?.policies.get(name);
    if (!t || !p) return;
    if (c.eat('rename', 'to')) {
      const nn = identValue(c.peek());
      if (!nn) return;
      t.policies.delete(name);
      p.name = nn;
      t.policies.set(nn, p);
      return;
    }
    this.policyClauses(c, p);
    p.loc = this.loc(st);
  }

  private alterSchema(c: Cursor, st: Statement): void {
    c.i++;
    const from = identValue(c.peek());
    c.i++;
    if (!from || !c.eat('rename', 'to')) return;
    const to = identValue(c.peek());
    if (!to) return;
    for (const t of [...this.tables.values()]) if (t.schema === from) this.move(t, to, t.name, this.loc(st));
    for (const k of [...this.defaults.keys()]) {
      const [s, role] = k.split('\u0000') as [string, string];
      if (s === from) {
        this.defaults.set(`${to}\u0000${role}`, this.defaults.get(k)!);
        this.defaults.delete(k);
      }
    }
  }

  // ALTER DEFAULT PRIVILEGES [FOR ROLE r] [IN SCHEMA s, ...] GRANT|REVOKE privs ON TABLES|FUNCTIONS TO|FROM roles
  private alterDefaultPrivileges(c: Cursor, st: Statement): void {
    if (!c.eat('default', 'privileges')) return;
    if (c.eat('for')) {
      c.eat('role') || c.eat('user');
      while (identValue(c.peek()) && !c.is('in') && !c.is('grant') && !c.is('revoke')) {
        c.i++;
        if (c.punct(',')) c.i++;
      }
    }
    let schemas = ['*'];
    if (c.eat('in', 'schema')) {
      schemas = [];
      for (;;) {
        const s = identValue(c.peek());
        if (!s) break;
        schemas.push(s);
        c.i++;
        if (c.punct(',')) {
          c.i++;
          continue;
        }
        break;
      }
    }
    const grant = c.word() === 'grant';
    if (!grant && c.word() !== 'revoke') return;
    c.i++;
    if (!grant) c.eat('grant', 'option', 'for');
    if (c.is('execute') || ((c.is('all') || c.is('all', 'privileges')) && this.onRoutines(c))) {
      // EXECUTE on functions / routines
      while (!c.done() && !c.is('on')) c.i++;
      if (!c.eat('on') || !(c.eat('functions') || c.eat('routines'))) return;
      if (!c.eat(grant ? 'to' : 'from')) return;
      const roles = this.roleList(c);
      for (const s of schemas) for (const r of roles) this.fnDefaults.set(`${s}\u0000${r}`, grant);
      if (grant) this.grantStatements.push({ kind: 'default', schemas, roles, privs: ['execute'], objects: 'functions', loc: this.loc(st), tables: [], relocked: [] });
      return;
    }
    const privs = this.privileges(c);
    if (!c.eat('on', 'tables')) return;
    if (!c.eat(grant ? 'to' : 'from')) return;
    const roles = this.roleList(c);
    if (grant) this.grantStatements.push({ kind: 'default', schemas, roles, privs, objects: 'tables', loc: this.loc(st), tables: [], relocked: [] });
    for (const s of schemas)
      for (const r of roles) {
        const k = `${s}\u0000${r}`;
        const set = this.defaults.get(k) ?? new Set<Privilege>();
        privs.forEach((p) => (grant ? set.add(p) : set.delete(p)));
        this.defaults.set(k, set);
      }
  }

  /** Is the privilege list at the cursor followed by `ON FUNCTIONS` / `ON ROUTINES`? (does not move the cursor) */
  private onRoutines(c: Cursor): boolean {
    for (let k = c.i; k < c.t.length; k++) {
      const t = c.t[k]!;
      if (t.type === 'word' && t.value === 'on') {
        const n = c.t[k + 1];
        return n?.type === 'word' && (n.value === 'functions' || n.value === 'routines');
      }
    }
    return false;
  }

  // ------------------------------------------------------------ DROP

  private drop(c: Cursor, st: Statement): void {
    c.i++;
    const what = c.word();
    if (what === 'view' || (what === 'materialized' && c.word(1) === 'view')) {
      c.i += what === 'view' ? 1 : 2;
      c.eat('if', 'exists');
      for (const g of c.restByComma()) {
        const parts = new Cursor(g).name();
        const v = parts ? this.resolveView(parts) : undefined;
        if (v) this.views.delete(tableKey(v.schema, v.name));
      }
      return;
    }
    if (what === 'function' || what === 'procedure' || what === 'routine') {
      c.i++;
      c.eat('if', 'exists');
      for (const g of c.restByComma()) {
        const parts = new Cursor(g).name();
        if (!parts) continue;
        const { schema, name } = this.resolveFn(parts);
        this.functions.delete(fnKey(schema, name));
      }
      return;
    }
    if (what === 'trigger') {
      c.i++;
      c.eat('if', 'exists');
      const name = identValue(c.peek());
      c.i++;
      if (!name || !c.eat('on')) return;
      const parts = c.name();
      const t = parts ? this.lookup(parts) : undefined;
      t?.triggers.delete(name);
      return;
    }
    if (what === 'publication') {
      c.i++;
      c.eat('if', 'exists');
      for (const g of c.restByComma()) {
        const n = identValue(g[0]);
        if (n) this.publications.delete(n);
      }
      return;
    }
    if (what === 'policy') {
      c.i++;
      c.eat('if', 'exists');
      const name = identValue(c.peek());
      c.i++;
      if (!name || !c.eat('on')) return;
      const parts = c.name();
      const t = parts ? this.lookup(parts) : undefined;
      t?.policies.delete(name);
      return;
    }
    if (what === 'schema') {
      c.i++;
      c.eat('if', 'exists');
      const names = c.restByComma().map((g) => identValue(g[0])).filter((x): x is string => !!x);
      for (const t of [...this.tables.values()]) if (names.includes(t.schema)) this.tables.delete(tableKey(t.schema, t.name));
      return;
    }
    if (what !== 'table') return;
    c.i++;
    c.eat('if', 'exists');
    void st;
    for (const g of c.restByComma()) {
      const parts = new Cursor(g).name();
      const t = parts ? this.lookup(parts) : undefined;
      if (!t) continue;
      this.tables.delete(tableKey(t.schema, t.name));
      // DROP TABLE ... CASCADE takes dependent views with it (without CASCADE Postgres refuses).
      for (const [k, v] of [...this.views]) if (v.sources.includes(t)) this.views.delete(k);
      if (t.kind === 'partitioned') {
        for (const child of [...this.tables.values()]) if (child.parent === tableKey(t.schema, t.name)) this.tables.delete(tableKey(child.schema, child.name));
      }
    }
  }

  // ------------------------------------------------------------ GRANT / REVOKE

  private privileges(c: Cursor): Privilege[] {
    return this.privilegeItems(c).map((x) => x.priv);
  }

  /** Privilege list with optional column lists: `select (a, b), update` -> [{select,[a,b]}, {update,null}]. */
  private privilegeItems(c: Cursor): { priv: Privilege; cols: string[] | null }[] {
    if (c.eat('all')) {
      c.eat('privileges');
      const cols = c.punct('(') ? this.columnList(c.group() ?? []) : null;
      return ALL_PRIVS.map((priv) => ({ priv, cols }));
    }
    const out: { priv: Privilege; cols: string[] | null }[] = [];
    for (;;) {
      const w = c.word();
      if (!w || !(ALL_PRIVS as string[]).includes(w)) break;
      c.i++;
      const cols = c.punct('(') ? this.columnList(c.group() ?? []) : null;
      out.push({ priv: w as Privilege, cols });
      if (c.punct(',')) {
        c.i++;
        continue;
      }
      break;
    }
    return out;
  }

  private columnList(tokens: Token[]): string[] {
    return splitByComma(tokens)
      .map((g) => identValue(g[0]))
      .filter((x): x is string => !!x);
  }

  private roleList(c: Cursor): string[] {
    const roles: string[] = [];
    for (;;) {
      c.eat('group');
      const r = identValue(c.peek());
      if (!r) break;
      roles.push(r);
      c.i++;
      if (c.punct(',')) {
        c.i++;
        continue;
      }
      break;
    }
    return roles;
  }

  private schemaList(c: Cursor): string[] {
    const schemas: string[] = [];
    for (;;) {
      const s = identValue(c.peek());
      if (!s) break;
      schemas.push(s);
      c.i++;
      if (c.punct(',')) {
        c.i++;
        continue;
      }
      break;
    }
    return schemas;
  }

  private grantRevoke(c: Cursor, st: Statement, grant: boolean): void {
    c.i++;
    if (!grant) c.eat('grant', 'option', 'for');
    // EXECUTE / ALL on functions
    const save = c.i;
    if (c.word() === 'execute' || c.word() === 'all') {
      c.eat('execute') || (c.eat('all') && (c.eat('privileges'), true));
      if (c.eat('on')) {
        if (c.eat('all', 'functions', 'in', 'schema') || c.eat('all', 'routines', 'in', 'schema') || c.eat('all', 'procedures', 'in', 'schema')) {
          const schemas = this.schemaList(c);
          if (!c.eat(grant ? 'to' : 'from')) return;
          const roles = this.roleList(c);
          for (const f of this.functions.values()) if (schemas.includes(f.schema)) for (const r of roles) grant ? f.execute.add(r) : f.execute.delete(r);
          return;
        }
        if (c.eat('function') || c.eat('procedure') || c.eat('routine')) {
          const fns: FunctionState[] = [];
          for (;;) {
            const parts = c.name();
            if (!parts) break;
            if (c.punct('(')) c.group();
            const { schema, name } = this.resolveFn(parts);
            const f = this.functions.get(fnKey(schema, name));
            if (f) fns.push(f);
            if (c.punct(',')) {
              c.i++;
              continue;
            }
            break;
          }
          if (!c.eat(grant ? 'to' : 'from')) return;
          const roles = this.roleList(c);
          for (const f of fns) for (const r of roles) grant ? f.execute.add(r) : f.execute.delete(r);
          return;
        }
      }
      c.i = save;
    }
    const items = this.privilegeItems(c);
    if (items.length === 0 || !c.eat('on')) return;
    let targets: TableState[] = [];
    let viewTargets: ViewState[] = [];
    let allIn: string[] | null = null;
    if (c.eat('all', 'tables', 'in', 'schema')) {
      allIn = this.schemaList(c);
      targets = [...this.tables.values()].filter((t) => allIn!.includes(t.schema));
      viewTargets = [...this.views.values()].filter((v) => allIn!.includes(v.schema));
    } else {
      const w = c.word();
      if (w && ['sequence', 'function', 'procedure', 'routine', 'schema', 'database', 'domain', 'foreign', 'language', 'large', 'tablespace', 'type', 'all'].includes(w)) return;
      c.eat('table');
      for (;;) {
        const parts = c.name();
        if (!parts) break;
        const view = this.lookup(parts) ? undefined : this.resolveView(parts);
        if (view) viewTargets.push(view);
        else targets.push(this.lookupOrStub(parts, st));
        if (c.punct(',')) {
          c.i++;
          continue;
        }
        break;
      }
    }
    if (!c.eat(grant ? 'to' : 'from')) return;
    const roles = this.roleList(c);
    const loc = this.loc(st);
    if (allIn && grant) {
      const relocked = roles.some((r) => r === 'anon' || r === 'public') ? targets.filter((t) => t.anonRevokedAt) : [];
      this.grantStatements.push({ kind: 'all-tables', schemas: allIn, roles, privs: [...new Set(items.map((x) => x.priv))], objects: 'tables', loc, tables: targets, relocked });
    }
    for (const t of targets)
      for (const r of roles) {
        if (!grant && (r === 'anon' || r === 'public') && items.some((x) => !x.cols)) t.anonRevokedAt = loc;
        const set = t.grants.get(r) ?? new Set<Privilege>();
        for (const { priv, cols } of items) {
          // A column list grants those columns only: kept apart from the table-level privilege.
          if (grant && !cols) set.add(priv);
          else if (!grant && !cols) set.delete(priv);
          if (cols && grant) t.columnGrants.push({ role: r, priv, columns: cols, loc });
          if (!grant) {
            // REVOKE on columns removes those column grants; a table-level REVOKE removes them all.
            t.columnGrants = t.columnGrants
              .map((g) => (g.role === r && g.priv === priv ? { ...g, columns: cols ? g.columns.filter((x) => !cols.includes(x)) : [] } : g))
              .filter((g) => g.columns.length > 0);
          }
        }
        t.grants.set(r, set);
      }
    for (const v of viewTargets)
      for (const r of roles) {
        const set = v.grants.get(r) ?? new Set<Privilege>();
        for (const { priv, cols } of items) {
          if (grant) set.add(priv);
          else if (!cols) set.delete(priv);
        }
        v.grants.set(r, set);
      }
  }

  // ------------------------------------------------------------ functions

  private static readonly FN_OPTION_WORDS = new Set([
    'language', 'security', 'external', 'set', 'as', 'immutable', 'stable', 'volatile', 'strict', 'called', 'leakproof',
    'parallel', 'cost', 'rows', 'support', 'window', 'begin', 'return', 'not', 'transform', 'returns',
  ]);

  /** Tokens of an option value, up to the next top-level option keyword. */
  private optionValue(c: Cursor): Token[] {
    const out: Token[] = [];
    while (!c.done()) {
      const t = c.peek()!;
      if (t.type === 'word' && Replayer.FN_OPTION_WORDS.has(t.value) && out.length > 0) break;
      if (t.type === 'punct' && t.value === '(') {
        const start = c.i;
        c.group();
        out.push(...c.t.slice(start, c.i));
        continue;
      }
      out.push(t);
      c.i++;
    }
    return out;
  }

  /** `SET search_path {TO|=} a, b` / `FROM CURRENT` -> the path text. Cursor is after `search_path`. */
  private searchPathValue(c: Cursor): string {
    if (c.eat('from', 'current')) return this.searchPath.join(', ');
    if (!c.eat('to') && c.peek()?.type === 'op' && c.peek()!.value === '=') c.i++;
    const vals: string[] = [];
    for (const t of this.optionValue(c)) {
      if (t.type === 'punct' && t.value === ',') continue;
      if (t.type === 'string') vals.push(t.value.trim() === '' ? "''" : t.value.trim());
      else if (t.type === 'word' || t.type === 'qident') vals.push(t.value);
    }
    return vals.join(', ');
  }

  private createFunction(c: Cursor, st: Statement, orReplace: boolean): void {
    const kind = c.word() === 'procedure' ? 'procedure' : 'function';
    c.i++;
    const parts = c.name();
    if (!parts) return;
    const argTokens = c.group() ?? [];
    const schema = parts.length >= 2 ? parts[parts.length - 2]! : this.creationSchema();
    const name = parts[parts.length - 1]!;
    const f: FunctionState = {
      schema,
      name,
      kind,
      args: textOf(argTokens, this.src),
      returns: '',
      language: '',
      securityDefiner: false,
      searchPath: null,
      body: '',
      bodyLine: st.line,
      loc: this.loc(st),
      createPath: [...this.searchPath],
      execute: this.defaultExecute(schema),
    };
    while (!c.done()) {
      if (c.eat('returns')) {
        f.returns = textOf(this.optionValue(c), this.src).toLowerCase();
        continue;
      }
      if (c.eat('language')) {
        const t = c.peek();
        f.language = (t?.type === 'string' ? t.value : identValue(t) ?? '').toLowerCase();
        c.i++;
        continue;
      }
      if (c.eat('external', 'security', 'definer') || c.eat('security', 'definer')) {
        f.securityDefiner = true;
        continue;
      }
      if (c.eat('external', 'security', 'invoker') || c.eat('security', 'invoker')) {
        f.securityDefiner = false;
        continue;
      }
      if (c.eat('set')) {
        const param = identValue(c.peek());
        c.i++;
        if (param === 'search_path') f.searchPath = this.searchPathValue(c);
        else this.optionValue(c);
        continue;
      }
      if (c.eat('as')) {
        const t = c.peek();
        if (t && (t.type === 'string' || t.type === 'dollar')) {
          f.body = t.value;
          f.bodyLine = lineAt(this.src, t.start);
          c.i++;
        }
        continue;
      }
      if (c.is('begin', 'atomic') || c.is('return')) {
        const rest = c.t.slice(c.i);
        f.body = textOf(rest, this.src);
        f.bodyLine = lineAt(this.src, rest[0]!.start);
        break;
      }
      c.i++;
    }
    const prev = this.functions.get(fnKey(schema, name));
    // CREATE OR REPLACE keeps the existing privileges.
    if (prev && orReplace) f.execute = prev.execute;
    else if (prev) return; // plain CREATE of an existing name fails (same signature) or adds an overload: keep the first
    this.functions.set(fnKey(schema, name), f);
  }

  private alterFunction(c: Cursor, st: Statement): void {
    c.i++;
    c.eat('if', 'exists');
    const parts = c.name();
    if (!parts) return;
    if (c.punct('(')) c.group();
    const { schema, name } = this.resolveFn(parts);
    const f = this.functions.get(fnKey(schema, name));
    if (!f) return;
    while (!c.done()) {
      if (c.eat('external', 'security', 'definer') || c.eat('security', 'definer')) {
        f.securityDefiner = true;
        f.loc = this.loc(st);
        continue;
      }
      if (c.eat('external', 'security', 'invoker') || c.eat('security', 'invoker')) {
        f.securityDefiner = false;
        continue;
      }
      if (c.eat('set', 'schema')) {
        const ns = identValue(c.peek());
        c.i++;
        if (ns) {
          this.functions.delete(fnKey(f.schema, f.name));
          f.schema = ns;
          this.functions.set(fnKey(f.schema, f.name), f);
        }
        continue;
      }
      if (c.eat('set')) {
        const param = identValue(c.peek());
        c.i++;
        if (param === 'search_path') f.searchPath = this.searchPathValue(c);
        else this.optionValue(c);
        continue;
      }
      if (c.eat('reset', 'search_path') || c.eat('reset', 'all')) {
        f.searchPath = null;
        continue;
      }
      if (c.eat('rename', 'to')) {
        const nn = identValue(c.peek());
        c.i++;
        if (nn) {
          this.functions.delete(fnKey(f.schema, f.name));
          f.name = nn;
          this.functions.set(fnKey(f.schema, f.name), f);
        }
        continue;
      }
      c.i++;
    }
  }

  // ------------------------------------------------------------ triggers

  private createTrigger(c: Cursor, st: Statement): void {
    c.eat('constraint');
    c.i++; // trigger
    const name = identValue(c.peek());
    if (!name) return;
    c.i++;
    let timing = '';
    if (c.eat('before')) timing = 'before';
    else if (c.eat('after')) timing = 'after';
    else if (c.eat('instead', 'of')) timing = 'instead of';
    const events: string[] = [];
    while (!c.done() && !c.is('on')) {
      const w = c.word();
      if (w === 'insert' || w === 'update' || w === 'delete' || w === 'truncate') events.push(w);
      c.i++;
    }
    if (!c.eat('on')) return;
    const parts = c.name();
    if (!parts) return;
    while (!c.done() && !(c.is('execute', 'function') || c.is('execute', 'procedure'))) c.i++;
    if (!c.eat('execute')) return;
    c.i++;
    const fnParts = c.name();
    if (!fnParts) return;
    const t = this.lookupOrStub(parts, st);
    t.triggers.set(name, { name, timing, events, fnParts, fnPath: [...this.searchPath], loc: this.loc(st) });
  }

  // ------------------------------------------------------------ views

  private createView(c: Cursor, st: Statement): void {
    const materialized = c.eat('materialized');
    c.eat('recursive');
    c.i++; // view
    c.eat('if', 'not', 'exists');
    const parts = c.name();
    if (!parts) return;
    if (c.punct('(')) c.group();
    let invoker: boolean | null = null;
    while (!c.done() && !c.is('as')) {
      if (c.eat('with') && c.punct('(')) {
        const opt = viewOption(c.group() ?? []);
        if (opt !== null) invoker = opt;
        continue;
      }
      c.i++;
    }
    if (!c.eat('as')) return;
    const query = c.t.slice(c.i);
    const schema = parts.length >= 2 ? parts[parts.length - 2]! : this.creationSchema();
    const name = parts[parts.length - 1]!;
    const prev = this.views.get(tableKey(schema, name));
    const v: ViewState = {
      schema,
      name,
      materialized,
      // CREATE OR REPLACE VIEW without WITH (...) resets the options (checked on PG16): security_invoker is lost.
      securityInvoker: invoker ?? false,
      sources: this.querySources(query),
      callerScoped: callerScoped(query),
      loc: this.loc(st),
      grants: prev ? prev.grants : this.defaultGrants(schema),
    };
    this.views.set(tableKey(schema, name), v);
  }

  /** Tables a query reads: names after FROM / JOIN (and comma-separated FROM items), views expanded. */
  private querySources(q: Token[]): TableState[] {
    const out = new Set<TableState>();
    const add = (parts: string[]): void => {
      const t = this.lookup(parts);
      if (t) {
        out.add(t);
        return;
      }
      const v = this.resolveView(parts);
      if (v) v.sources.forEach((x) => out.add(x));
    };
    for (let k = 0; k < q.length; k++) {
      const t = q[k]!;
      if (t.type !== 'word' || (t.value !== 'from' && t.value !== 'join')) continue;
      let j = k + 1;
      for (;;) {
        if (q[j]?.type === 'word' && (q[j]!.value === 'only' || q[j]!.value === 'lateral')) j++;
        const cur = new Cursor(q);
        cur.i = j;
        const parts = cur.name();
        if (!parts) break;
        add(parts);
        j = cur.i;
        // optional alias
        if (q[j]?.type === 'word' && q[j]!.value === 'as') j++;
        if ((q[j]?.type === 'word' && !VIEW_STOP.has(q[j]!.value)) || q[j]?.type === 'qident') j++;
        if (t.value === 'from' && q[j]?.type === 'punct' && q[j]!.value === ',') {
          j++;
          continue;
        }
        break;
      }
    }
    return [...out];
  }

  private alterView(c: Cursor, st: Statement): void {
    c.eat('materialized');
    c.i++; // view
    c.eat('if', 'exists');
    const parts = c.name();
    if (!parts) return;
    const v = this.resolveView(parts);
    if (!v) return;
    if (c.eat('set', 'schema')) {
      const ns = identValue(c.peek());
      if (ns) {
        this.views.delete(tableKey(v.schema, v.name));
        v.schema = ns;
        this.views.set(tableKey(v.schema, v.name), v);
      }
      return;
    }
    if (c.eat('rename', 'to')) {
      const nn = identValue(c.peek());
      if (nn) {
        this.views.delete(tableKey(v.schema, v.name));
        v.name = nn;
        this.views.set(tableKey(v.schema, v.name), v);
      }
      return;
    }
    if (c.eat('set') && c.punct('(')) {
      const opt = viewOption(c.group() ?? []);
      if (opt !== null) {
        v.securityInvoker = opt;
        v.loc = this.loc(st);
      }
      return;
    }
    if (c.eat('reset') && c.punct('(')) {
      const g = c.group() ?? [];
      if (g.some((t) => t.type === 'word' && t.value === 'security_invoker')) {
        v.securityInvoker = false;
        v.loc = this.loc(st);
      }
    }
  }

  // ------------------------------------------------------------ publications (Realtime)

  private publicationItems(c: Cursor, pub: PublicationState, mode: 'add' | 'drop' | 'set', st: Statement): void {
    if (mode === 'set') {
      pub.tables.clear();
      pub.schemas.clear();
    }
    if (c.eat('all', 'tables')) {
      pub.allTables = mode !== 'drop';
      return;
    }
    for (const item of c.restByComma()) {
      const ic = new Cursor(item);
      if (ic.eat('tables', 'in', 'schema')) {
        const s = identValue(ic.peek());
        if (s) mode === 'drop' ? pub.schemas.delete(s) : pub.schemas.add(s);
        continue;
      }
      ic.eat('table');
      ic.eat('only');
      const parts = ic.name();
      if (!parts) continue;
      const t = this.lookupOrStub(parts, st);
      if (mode === 'drop') pub.tables.delete(t);
      else pub.tables.set(t, this.loc(st));
    }
  }

  private createPublication(c: Cursor, st: Statement): void {
    c.i++;
    const name = identValue(c.peek());
    if (!name) return;
    c.i++;
    const pub: PublicationState = { name, allTables: false, schemas: new Set(), tables: new Map(), loc: this.loc(st) };
    this.publications.set(name, pub);
    if (c.eat('for')) this.publicationItems(c, pub, 'add', st);
  }

  private alterPublication(c: Cursor, st: Statement): void {
    c.i++;
    const name = identValue(c.peek());
    if (!name) return;
    c.i++;
    // supabase_realtime is created by the platform, not by the user's migrations.
    let pub = this.publications.get(name);
    if (!pub) {
      pub = { name, allTables: false, schemas: new Set(), tables: new Map(), loc: this.loc(st) };
      this.publications.set(name, pub);
    }
    const mode = c.eat('add') ? 'add' : c.eat('drop') ? 'drop' : c.eat('set') ? 'set' : null;
    if (!mode) return;
    this.publicationItems(c, pub, mode, st);
  }

  // ------------------------------------------------------------ storage.buckets

  private isBuckets(parts: string[] | null): boolean {
    if (!parts) return false;
    if (parts.length >= 2) return parts[parts.length - 2] === 'storage' && parts[parts.length - 1] === 'buckets';
    return parts[0] === 'buckets' && this.searchPath.includes('storage');
  }

  private insertBuckets(c: Cursor, st: Statement): void {
    if (!c.eat('insert', 'into')) return;
    if (!this.isBuckets(c.name())) return;
    if (c.word() === 'as') c.i += 2;
    const cols = c.punct('(') ? this.columnList(c.group() ?? []) : null;
    if (!cols || !c.eat('values')) return;
    const rows: { id: string; pub: boolean | null }[] = [];
    while (c.punct('(')) {
      const vals = splitByComma(c.group() ?? []);
      const idTok = vals[cols.indexOf('id')]?.[0] ?? vals[cols.indexOf('name')]?.[0];
      const pi = cols.indexOf('public');
      const id = idTok?.type === 'string' ? idTok.value : null;
      if (id) rows.push({ id, pub: pi >= 0 ? boolLiteral(vals[pi] ?? []) : false });
      if (c.punct(',')) c.i++;
    }
    let onConflict: 'nothing' | 'update' | null = null;
    let updatePublic: boolean | 'excluded' | null = null;
    if (c.eat('on', 'conflict')) {
      while (!c.done() && !c.is('do')) c.i++;
      if (c.eat('do', 'nothing')) onConflict = 'nothing';
      else if (c.eat('do', 'update', 'set')) {
        onConflict = 'update';
        for (const a of c.restByComma()) {
          if (identValue(a[0]) !== 'public') continue;
          const rhs = a.slice(2);
          updatePublic = rhs.some((t) => t.type === 'word' && t.value === 'excluded') ? 'excluded' : boolLiteral(rhs);
        }
      }
    }
    for (const r of rows) {
      const prev = this.buckets.get(r.id);
      if (prev) {
        if (onConflict !== 'update') continue; // duplicate key (error) or DO NOTHING
        const v = updatePublic === 'excluded' ? r.pub : updatePublic;
        if (v !== null) this.buckets.set(r.id, { id: r.id, public: v, loc: this.loc(st) });
        continue;
      }
      this.buckets.set(r.id, { id: r.id, public: r.pub === true, loc: this.loc(st) });
    }
  }

  /** Bucket ids a `WHERE id = 'x'` / `name = 'x'` / `id in ('a', 'b')` selects; null = every bucket; undefined = cannot tell. */
  private bucketTargets(c: Cursor): string[] | null | undefined {
    if (c.done()) return null;
    if (!c.eat('where')) return undefined;
    const rest = c.t.slice(c.i);
    if (rest.some((t) => t.type === 'word' && (t.value === 'or' || t.value === 'not'))) return undefined;
    const ids: string[] = [];
    for (let k = 0; k < rest.length; k++) {
      const t = rest[k]!;
      if (t.type !== 'word' || (t.value !== 'id' && t.value !== 'name')) continue;
      const n = rest[k + 1];
      if (n?.type === 'op' && n.value === '=' && rest[k + 2]?.type === 'string') ids.push(rest[k + 2]!.value);
      if (n?.type === 'word' && n.value === 'in') {
        for (let j = k + 2; j < rest.length && !(rest[j]!.type === 'punct' && rest[j]!.value === ')'); j++) if (rest[j]!.type === 'string') ids.push(rest[j]!.value);
      }
    }
    return ids.length ? ids : undefined;
  }

  private updateBuckets(c: Cursor, st: Statement): void {
    c.i++;
    c.eat('only');
    if (!this.isBuckets(c.name())) return;
    if (!c.eat('set')) return;
    let pub: boolean | null = null;
    const assigns: Token[][] = [];
    let cur: Token[] = [];
    let depth = 0;
    for (; !c.done() && !(depth === 0 && c.is('where')); c.i++) {
      const t = c.peek()!;
      if (t.type === 'punct' && t.value === '(') depth++;
      if (t.type === 'punct' && t.value === ')') depth--;
      if (depth === 0 && t.type === 'punct' && t.value === ',') {
        assigns.push(cur);
        cur = [];
        continue;
      }
      cur.push(t);
    }
    if (cur.length) assigns.push(cur);
    for (const a of assigns) if (identValue(a[0]) === 'public') pub = boolLiteral(a.slice(2));
    if (pub === null) return;
    const targets = this.bucketTargets(c);
    if (targets === undefined) return;
    const ids = targets ?? [...this.buckets.keys()];
    for (const id of ids) this.buckets.set(id, { id, public: pub, loc: this.loc(st) });
  }

  private deleteBuckets(c: Cursor): void {
    if (!c.eat('delete', 'from')) return;
    if (!this.isBuckets(c.name())) return;
    const targets = this.bucketTargets(c);
    if (targets === undefined) return;
    for (const id of targets ?? [...this.buckets.keys()]) this.buckets.delete(id);
  }

  // ------------------------------------------------------------ search_path

  private setPath(c: Cursor): void {
    if (c.word() === 'reset') {
      if (c.is('reset', 'search_path') || c.is('reset', 'all')) this.searchPath = ['public'];
      return;
    }
    c.i++;
    c.eat('session') || c.eat('local');
    if (!c.eat('search_path')) return;
    if (!c.eat('to') && !(c.peek()?.type === 'op' && c.peek()!.value === '=' && c.i++ >= 0)) return;
    if (c.eat('default')) {
      this.searchPath = ['public'];
      return;
    }
    const path: string[] = [];
    for (const g of c.restByComma()) {
      const t = g[0];
      if (!t) continue;
      if (t.type === 'string') path.push(...t.value.split(',').map((s) => s.trim().replace(/^"|"$/g, '')).filter(Boolean));
      else {
        const v = identValue(t);
        if (v) path.push(v);
      }
    }
    this.searchPath = path;
  }

  /** pg_dump's `SELECT pg_catalog.set_config('search_path', '', false);` */
  private selectSetConfig(st: Statement): void {
    const t = st.tokens;
    const k = t.findIndex((x) => x.type === 'word' && x.value === 'set_config');
    if (k < 0) return;
    const key = t[k + 2];
    const val = t[k + 4];
    if (key?.type !== 'string' || key.value.toLowerCase() !== 'search_path' || val?.type !== 'string') return;
    const path = val.value.split(',').map((s) => s.trim().replace(/^"|"$/g, '')).filter(Boolean);
    this.searchPath = path.length ? path : ['public'];
  }

  // ------------------------------------------------------------ DO blocks

  private doBlock(c: Cursor, st: Statement, depth: number): void {
    const body = st.tokens.find((t) => t.type === 'dollar' || t.type === 'string');
    if (!body) return;
    const lang = st.tokens.findIndex((t) => t.type === 'word' && t.value === 'language');
    const langName = lang >= 0 ? identValue(st.tokens[lang + 1]) : 'plpgsql';
    if (langName !== 'plpgsql') return;
    void c;
    const outerSrc = this.src;
    const bodyLine = lineAt(outerSrc, body.start);
    const src = body.value;
    const chunks = splitStatements(src, bodyLine - 1);
    this.src = src;
    for (const chunk of chunks) {
      const toks = chunk.tokens;
      // `execute '<literal sql>'`
      const ex = toks.findIndex((t) => t.type === 'word' && t.value === 'execute');
      if (ex >= 0) {
        const lit = toks[ex + 1];
        const next = toks[ex + 2];
        if ((lit?.type === 'string' || lit?.type === 'dollar') && !next) {
          this.src = outerSrc;
          this.runSource(lit.value, chunk.line - 1, depth + 1);
          this.src = src;
        } else if (/row\s+level\s+security/i.test(chunk.text)) {
          for (const t of this.tables.values()) t.rlsUncertain = true;
          this.rlsUsed = true;
        }
        continue;
      }
      // the first statement keyword in the chunk (after BEGIN / IF ... THEN / ELSE / LOOP)
      const k = toks.findIndex(
        (t, idx) =>
          t.type === 'word' &&
          ['alter', 'create', 'drop', 'grant', 'revoke'].includes(t.value) &&
          (idx === 0 || (toks[idx - 1]!.type === 'word' && ['begin', 'then', 'else', 'loop', 'declare'].includes(toks[idx - 1]!.value)) ||
            (toks[idx - 1]!.type === 'punct' && toks[idx - 1]!.value === ';')),
      );
      if (k < 0) continue;
      const stmt: Statement = { tokens: toks.slice(k), line: lineAt(src, toks[k]!.start) + bodyLine - 1, text: chunk.text };
      try {
        this.statement(stmt, depth + 1);
      } catch {
        // tolerant
      }
    }
    this.src = outerSrc;
  }
}

const VIEW_STOP = new Set([
  'where', 'join', 'inner', 'left', 'right', 'full', 'cross', 'natural', 'on', 'using', 'group', 'order', 'limit', 'offset',
  'having', 'union', 'except', 'intersect', 'window', 'with', 'for', 'fetch', 'lateral', 'returning',
]);

/** `security_invoker` in a `WITH (...)` / `SET (...)` option list: true/false, or null when not mentioned. */
function viewOption(tokens: Token[]): boolean | null {
  for (const opt of splitByComma(tokens)) {
    if (opt[0]?.type !== 'word' || opt[0].value !== 'security_invoker') continue;
    const v = opt[2];
    if (!v) return true;
    const s = v.value.toLowerCase();
    return s === 'true' || s === 'on' || s === '1' || s === 'yes';
  }
  return null;
}

/** The query filters by the caller: auth.uid() / auth.jwt() / current_user. */
function callerScoped(q: Token[]): boolean {
  for (let k = 0; k < q.length; k++) {
    const t = q[k]!;
    if (t.type !== 'word') continue;
    if (t.value === 'current_user' || t.value === 'session_user') return true;
    if (t.value === 'auth' && q[k + 1]?.value === '.' && (q[k + 2]?.value === 'uid' || q[k + 2]?.value === 'jwt')) return true;
  }
  return false;
}

/** A boolean literal (`true`, `'t'`, `'true'::boolean`, `false`), or null. */
function boolLiteral(tokens: Token[]): boolean | null {
  const t = tokens[0];
  if (!t) return null;
  const v = t.value.toLowerCase();
  if ((t.type === 'word' || t.type === 'string') && ['true', 't', 'on', 'yes', '1'].includes(v)) return true;
  if ((t.type === 'word' || t.type === 'string') && ['false', 'f', 'off', 'no', '0'].includes(v)) return false;
  return null;
}

function lineAt(src: string, offset: number): number {
  let n = 1;
  for (let i = 0; i < offset && i < src.length; i++) if (src.charCodeAt(i) === 10) n++;
  return n;
}

export function replayMigrations(files: SqlSource[]): DbModel {
  return new Replayer().run(files);
}

/** Resolve the function a trigger runs in a replayed model. */
export function triggerFunction(model: DbModel, tr: TriggerState): FunctionState | undefined {
  const parts = tr.fnParts;
  if (parts.length >= 2) return model.functions.get(fnKey(parts[parts.length - 2]!, parts[parts.length - 1]!));
  for (const s of tr.fnPath) {
    const f = model.functions.get(fnKey(s, parts[0]!));
    if (f) return f;
  }
  return model.functions.get(fnKey('public', parts[0]!));
}
