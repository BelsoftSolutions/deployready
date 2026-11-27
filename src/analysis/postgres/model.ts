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
  parent?: string;
}

export interface DbModel {
  tables: Map<string, TableState>;
  /** True when any statement enabled RLS on any table (the project uses RLS). */
  rlsUsed: boolean;
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
  rlsUsed = false;
  private defaults = initialDefaults();
  private searchPath: string[] = ['public'];
  private file = '';
  private src = '';

  run(files: SqlSource[]): DbModel {
    for (const f of orderSqlFiles(files)) {
      this.file = f.relPath;
      this.searchPath = ['public']; // each migration file runs in a fresh session
      this.runSource(f.source, 0);
    }
    return { tables: this.tables, rlsUsed: this.rlsUsed };
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
    const grants = new Map<string, Set<Privilege>>();
    for (const [k, privs] of this.defaults) {
      const [s, role] = k.split('\u0000') as [string, string];
      if (s === schema || s === '*') {
        const g = grants.get(role) ?? new Set<Privilege>();
        privs.forEach((p) => g.add(p));
        grants.set(role, g);
      }
    }
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
    };
    this.tables.set(tableKey(schema, name), t);
    return t;
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
  }

  // ------------------------------------------------------------ CREATE

  private create(c: Cursor, st: Statement): void {
    c.i++;
    c.eat('or', 'replace');
    if (c.word() === 'policy') return this.createPolicy(c, st);
    if (c.word() === 'schema') return;
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
    if (what === 'default') return this.alterDefaultPrivileges(c);
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

  // ALTER DEFAULT PRIVILEGES [FOR ROLE r] [IN SCHEMA s, ...] GRANT|REVOKE privs ON TABLES TO|FROM roles
  private alterDefaultPrivileges(c: Cursor): void {
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
    const privs = this.privileges(c);
    if (!c.eat('on', 'tables')) return;
    if (!c.eat(grant ? 'to' : 'from')) return;
    const roles = this.roleList(c);
    for (const s of schemas)
      for (const r of roles) {
        const k = `${s}\u0000${r}`;
        const set = this.defaults.get(k) ?? new Set<Privilege>();
        privs.forEach((p) => (grant ? set.add(p) : set.delete(p)));
        this.defaults.set(k, set);
      }
  }

  // ------------------------------------------------------------ DROP

  private drop(c: Cursor, st: Statement): void {
    c.i++;
    const what = c.word();
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
      if (t.kind === 'partitioned') {
        for (const child of [...this.tables.values()]) if (child.parent === tableKey(t.schema, t.name)) this.tables.delete(tableKey(child.schema, child.name));
      }
    }
  }

  // ------------------------------------------------------------ GRANT / REVOKE

  private privileges(c: Cursor): Privilege[] {
    if (c.eat('all')) {
      c.eat('privileges');
      if (c.punct('(')) c.group();
      return [...ALL_PRIVS];
    }
    const out: Privilege[] = [];
    for (;;) {
      const w = c.word();
      if (!w || !(ALL_PRIVS as string[]).includes(w)) break;
      out.push(w as Privilege);
      c.i++;
      if (c.punct('(')) c.group(); // column list: still a (partial) privilege
      if (c.punct(',')) {
        c.i++;
        continue;
      }
      break;
    }
    return out;
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

  private grantRevoke(c: Cursor, st: Statement, grant: boolean): void {
    c.i++;
    if (!grant) c.eat('grant', 'option', 'for');
    const privs = this.privileges(c);
    if (privs.length === 0 || !c.eat('on')) return;
    let targets: TableState[] = [];
    if (c.eat('all', 'tables', 'in', 'schema')) {
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
      targets = [...this.tables.values()].filter((t) => schemas.includes(t.schema));
    } else {
      const w = c.word();
      if (w && ['sequence', 'function', 'procedure', 'routine', 'schema', 'database', 'domain', 'foreign', 'language', 'large', 'tablespace', 'type', 'all'].includes(w)) return;
      c.eat('table');
      for (;;) {
        const parts = c.name();
        if (!parts) break;
        targets.push(this.lookupOrStub(parts, st));
        if (c.punct(',')) {
          c.i++;
          continue;
        }
        break;
      }
    }
    if (!c.eat(grant ? 'to' : 'from')) return;
    const roles = this.roleList(c);
    for (const t of targets)
      for (const r of roles) {
        const set = t.grants.get(r) ?? new Set<Privilege>();
        privs.forEach((p) => (grant ? set.add(p) : set.delete(p)));
        t.grants.set(r, set);
      }
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

function lineAt(src: string, offset: number): number {
  let n = 1;
  for (let i = 0; i < offset && i < src.length; i++) if (src.charCodeAt(i) === 10) n++;
  return n;
}

export function replayMigrations(files: SqlSource[]): DbModel {
  return new Replayer().run(files);
}
