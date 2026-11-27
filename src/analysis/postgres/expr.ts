/**
 * Policy expression parsing and classification.
 *
 * `parseExpr` turns the tokens inside USING (...) / WITH CHECK (...) into a small AST
 * (boolean logic, comparisons, IS / IN, casts, function calls, column refs, subqueries).
 * `evalFor` then evaluates it abstractly for one requesting role (anon or authenticated)
 * in Kleene three-valued logic: literal constants fold (`1 = 1`, `'a' = 'a'`, `true and true`,
 * `not false`, `x or true`, `col = col`), `auth.role()` / `current_user` / `auth.jwt() ->> 'role'`
 * become the role name, and `auth.uid()` is NULL for anon and an opaque non-null value for a
 * signed-in user. Anything we cannot know (column values, other functions, subqueries with a
 * FROM) is UNKNOWN. A policy is "open" for a role when its expression is TRUE for every row.
 *
 * Unparseable expressions yield `null`, which callers treat as restrictive (no finding).
 */
import type { Token } from './lexer';

export type Expr =
  | { k: 'const'; v: boolean | null | number | string }
  | { k: 'col'; parts: string[] }
  | { k: 'func'; name: string; args: Expr[] }
  | { k: 'bin'; op: string; l: Expr; r: Expr }
  | { k: 'and'; args: Expr[] }
  | { k: 'or'; args: Expr[] }
  | { k: 'not'; e: Expr }
  | { k: 'is'; e: Expr; test: 'null' | 'true' | 'false' | 'unknown' | 'distinct'; neg: boolean; r?: Expr }
  | { k: 'in'; e: Expr; list: Expr[] | null; neg: boolean; sub?: SubSelect }
  | { k: 'sub'; exists: boolean; sel: SubSelect }
  | { k: 'cast'; e: Expr; type: string }
  | { k: 'opaque' };

export interface FromItem {
  /** Qualified name parts as written (normalised identifiers). */
  name: string[];
  alias?: string;
}

export interface SubSelect {
  target: Expr | null;
  from: FromItem[];
  where: Expr | null;
  /** False when the FROM clause had joins or other forms we did not model. */
  simpleFrom: boolean;
}

class ParseError extends Error {}

const CMP_OPS = new Set(['=', '<>', '!=', '<', '>', '<=', '>=']);
const STOP_WORDS = new Set([
  'from', 'where', 'group', 'order', 'limit', 'offset', 'having', 'union', 'except', 'intersect', 'window', 'for', 'fetch',
  'then', 'else', 'end', 'when', 'and', 'or', 'as', 'on', 'join', 'inner', 'left', 'right', 'full', 'cross', 'natural', 'using',
]);
const NAMED_CONST_FUNCS = new Set(['current_user', 'session_user', 'current_role', 'user', 'current_date', 'current_timestamp', 'localtimestamp', 'now']);

export function identValue(t: Token | undefined): string | null {
  if (!t) return null;
  if (t.type === 'word' || t.type === 'qident') return t.value;
  return null;
}

class Parser {
  i = 0;
  constructor(private readonly t: Token[]) {}

  peek(o = 0): Token | undefined {
    return this.t[this.i + o];
  }
  isWord(v: string, o = 0): boolean {
    const t = this.peek(o);
    return t?.type === 'word' && t.value === v;
  }
  isPunct(v: string, o = 0): boolean {
    const t = this.peek(o);
    return t?.type === 'punct' && t.value === v;
  }
  isOp(v: string, o = 0): boolean {
    const t = this.peek(o);
    return t?.type === 'op' && t.value === v;
  }
  eatWord(v: string): boolean {
    if (this.isWord(v)) {
      this.i++;
      return true;
    }
    return false;
  }
  expectPunct(v: string): void {
    if (!this.isPunct(v)) throw new ParseError(`expected ${v}`);
    this.i++;
  }
  done(): boolean {
    return this.i >= this.t.length;
  }

  parseOr(): Expr {
    const args = [this.parseAnd()];
    while (this.eatWord('or')) args.push(this.parseAnd());
    return args.length === 1 ? args[0]! : { k: 'or', args };
  }
  parseAnd(): Expr {
    const args = [this.parseNot()];
    while (this.eatWord('and')) args.push(this.parseNot());
    return args.length === 1 ? args[0]! : { k: 'and', args };
  }
  parseNot(): Expr {
    if (this.eatWord('not')) return { k: 'not', e: this.parseNot() };
    return this.parseIs();
  }
  parseIs(): Expr {
    let e = this.parseCmp();
    for (;;) {
      if (this.isWord('is')) {
        this.i++;
        const neg = this.eatWord('not');
        if (this.eatWord('null')) e = { k: 'is', e, test: 'null', neg };
        else if (this.eatWord('true')) e = { k: 'is', e, test: 'true', neg };
        else if (this.eatWord('false')) e = { k: 'is', e, test: 'false', neg };
        else if (this.eatWord('unknown')) e = { k: 'is', e, test: 'unknown', neg };
        else if (this.eatWord('distinct')) {
          if (!this.eatWord('from')) throw new ParseError('distinct from');
          e = { k: 'is', e, test: 'distinct', neg, r: this.parseCmp() };
        } else throw new ParseError('is ?');
        continue;
      }
      if (this.eatWord('isnull')) {
        e = { k: 'is', e, test: 'null', neg: false };
        continue;
      }
      if (this.eatWord('notnull')) {
        e = { k: 'is', e, test: 'null', neg: true };
        continue;
      }
      return e;
    }
  }
  parseCmp(): Expr {
    let l = this.parsePred();
    for (;;) {
      const t = this.peek();
      if (t?.type === 'op' && CMP_OPS.has(t.value)) {
        this.i++;
        // `= any (...)` / `= all (...)`
        if ((this.isWord('any') || this.isWord('some') || this.isWord('all')) && this.isPunct('(', 1)) {
          const r = this.parsePred();
          l = { k: 'bin', op: t.value, l, r };
          continue;
        }
        l = { k: 'bin', op: t.value === '!=' ? '<>' : t.value, l, r: this.parsePred() };
        continue;
      }
      return l;
    }
  }
  parsePred(): Expr {
    const e = this.parseOther();
    const neg = this.isWord('not') && (this.isWord('in', 1) || this.isWord('like', 1) || this.isWord('ilike', 1) || this.isWord('between', 1) || this.isWord('similar', 1));
    if (neg) this.i++;
    if (this.eatWord('in')) {
      this.expectPunct('(');
      if (this.isWord('select') || this.isWord('with')) {
        const sub = this.parseSelectBody();
        this.expectPunct(')');
        return { k: 'in', e, list: null, neg, sub };
      }
      const list: Expr[] = [];
      if (!this.isPunct(')')) {
        list.push(this.parseOr());
        while (this.isPunct(',')) {
          this.i++;
          list.push(this.parseOr());
        }
      }
      this.expectPunct(')');
      return { k: 'in', e, list, neg };
    }
    if (this.eatWord('like') || this.eatWord('ilike')) {
      const r = this.parseOther();
      const b: Expr = { k: 'bin', op: 'like', l: e, r };
      return neg ? { k: 'not', e: b } : b;
    }
    if (this.eatWord('similar')) {
      this.eatWord('to');
      this.parseOther();
      return { k: 'opaque' };
    }
    if (this.eatWord('between')) {
      this.eatWord('symmetric');
      const lo = this.parseOther();
      if (!this.eatWord('and')) throw new ParseError('between');
      const hi = this.parseOther();
      const b: Expr = { k: 'and', args: [{ k: 'bin', op: '>=', l: e, r: lo }, { k: 'bin', op: '<=', l: e, r: hi }] };
      return neg ? { k: 'not', e: b } : b;
    }
    return e;
  }
  /** Any other binary operator (||, ->, ->>, @>, +, -, *, /, ...) at one precedence level. */
  parseOther(): Expr {
    let l = this.parseUnary();
    for (;;) {
      const t = this.peek();
      if (t?.type === 'op' && !CMP_OPS.has(t.value) && t.value !== '::') {
        this.i++;
        l = { k: 'bin', op: t.value, l, r: this.parseUnary() };
        continue;
      }
      return l;
    }
  }
  parseUnary(): Expr {
    const t = this.peek();
    if (t?.type === 'op' && (t.value === '-' || t.value === '+')) {
      this.i++;
      const e = this.parseUnary();
      if (e.k === 'const' && typeof e.v === 'number') return { k: 'const', v: t.value === '-' ? -e.v : e.v };
      return { k: 'func', name: `unary${t.value}`, args: [e] };
    }
    return this.parsePostfix();
  }
  parsePostfix(): Expr {
    let e = this.parsePrimary();
    for (;;) {
      if (this.isOp('::')) {
        this.i++;
        e = { k: 'cast', e, type: this.parseTypeName() };
        continue;
      }
      if (this.isPunct('[')) {
        this.skipBalanced('[', ']');
        e = { k: 'opaque' };
        continue;
      }
      return e;
    }
  }
  parseTypeName(): string {
    const parts: string[] = [];
    const first = identValue(this.peek());
    if (!first) throw new ParseError('type');
    this.i++;
    parts.push(first);
    while (this.isPunct('.') && identValue(this.peek(1))) {
      this.i++;
      parts.push(identValue(this.peek())!);
      this.i++;
    }
    // multi-word types: double precision, character varying, timestamp with time zone
    while (this.isWord('precision') || this.isWord('varying') || (this.isWord('with') && this.isWord('time', 1)) || (this.isWord('without') && this.isWord('time', 1))) {
      if (this.isWord('with') || this.isWord('without')) {
        this.i += 3;
      } else this.i++;
    }
    if (this.isPunct('(')) this.skipBalanced('(', ')');
    while (this.isPunct('[')) this.skipBalanced('[', ']');
    return parts.join('.');
  }
  skipBalanced(open: string, close: string): void {
    let depth = 0;
    do {
      const t = this.peek();
      if (!t) throw new ParseError('unbalanced');
      if (t.type === 'punct' && t.value === open) depth++;
      else if (t.type === 'punct' && t.value === close) depth--;
      this.i++;
    } while (depth > 0);
  }
  parseArgs(): Expr[] {
    this.expectPunct('(');
    const args: Expr[] = [];
    if (this.isPunct(')')) {
      this.i++;
      return args;
    }
    // `count(*)`, `f(distinct x)`, `f(variadic ...)`
    this.eatWord('distinct');
    this.eatWord('variadic');
    if (this.isOp('*')) {
      this.i++;
      this.expectPunct(')');
      return [{ k: 'opaque' }];
    }
    args.push(this.parseArg());
    while (this.isPunct(',')) {
      this.i++;
      args.push(this.parseArg());
    }
    if (this.isWord('order')) {
      // aggregate ORDER BY: not interesting
      while (!this.isPunct(')') && !this.done()) {
        if (this.isPunct('(')) this.skipBalanced('(', ')');
        else this.i++;
      }
    }
    this.expectPunct(')');
    return args;
  }
  parseArg(): Expr {
    // named notation: f(a => 1) / f(a := 1)
    if (identValue(this.peek()) && (this.isOp('=>', 1) || (this.isPunct(':', 1) && this.isOp('=', 2)))) {
      this.i += this.isOp('=>', 1) ? 2 : 3;
    }
    return this.parseOr();
  }
  parsePrimary(): Expr {
    const t = this.peek();
    if (!t) throw new ParseError('eof');
    if (t.type === 'punct' && t.value === '(') {
      this.i++;
      if (this.isWord('select') || this.isWord('with')) {
        const sel = this.parseSelectBody();
        this.expectPunct(')');
        return { k: 'sub', exists: false, sel };
      }
      const e = this.parseOr();
      if (this.isPunct(',')) {
        // row constructor (a, b): opaque
        while (!this.isPunct(')')) {
          if (this.done()) throw new ParseError('row');
          this.i++;
        }
        this.i++;
        return { k: 'opaque' };
      }
      this.expectPunct(')');
      return e;
    }
    if (t.type === 'number') {
      this.i++;
      return { k: 'const', v: Number(t.value) };
    }
    if (t.type === 'string' || t.type === 'dollar') {
      this.i++;
      return { k: 'const', v: t.value };
    }
    if (t.type === 'param') {
      this.i++;
      return { k: 'opaque' };
    }
    if (t.type === 'qident' || t.type === 'word') {
      if (t.type === 'word') {
        switch (t.value) {
          case 'true':
            this.i++;
            return { k: 'const', v: true };
          case 'false':
            this.i++;
            return { k: 'const', v: false };
          case 'null':
            this.i++;
            return { k: 'const', v: null };
          case 'exists': {
            this.i++;
            this.expectPunct('(');
            const sel = this.parseSelectBody();
            this.expectPunct(')');
            return { k: 'sub', exists: true, sel };
          }
          case 'case':
            return this.parseCase();
          case 'array':
            this.i++;
            if (this.isPunct('[')) {
              this.skipBalanced('[', ']');
              return { k: 'opaque' };
            }
            if (this.isPunct('(')) {
              this.skipBalanced('(', ')');
              return { k: 'opaque' };
            }
            throw new ParseError('array');
          case 'cast': {
            if (!this.isPunct('(', 1)) break;
            this.i += 2;
            const e = this.parseOr();
            if (!this.eatWord('as')) throw new ParseError('cast as');
            const type = this.parseTypeName();
            this.expectPunct(')');
            return { k: 'cast', e, type };
          }
          case 'interval':
          case 'date':
          case 'timestamp':
          case 'timestamptz':
          case 'time':
          case 'boolean':
          case 'bool':
          case 'text':
          case 'uuid':
          case 'int':
          case 'integer':
          case 'numeric':
          case 'jsonb':
          case 'json':
            // type 'literal' form
            if (this.peek(1)?.type === 'string') {
              this.i++;
              const s = this.peek()!;
              this.i++;
              return { k: 'cast', e: { k: 'const', v: s.value }, type: t.value };
            }
            break;
          default:
            break;
        }
        if (NAMED_CONST_FUNCS.has(t.value) && !this.isPunct('(', 1) && !this.isPunct('.', 1)) {
          this.i++;
          return { k: 'func', name: t.value, args: [] };
        }
        if (STOP_WORDS.has(t.value) && t.value !== 'using') throw new ParseError(`unexpected ${t.value}`);
      }
      // qualified name, possibly a function call
      const parts = [t.value];
      this.i++;
      while (this.isPunct('.')) {
        const nx = this.peek(1);
        if (nx && (nx.type === 'word' || nx.type === 'qident')) {
          parts.push(nx.value);
          this.i += 2;
        } else if (nx?.type === 'op' && nx.value === '*') {
          this.i += 2;
          return { k: 'opaque' };
        } else break;
      }
      if (this.isPunct('(')) {
        const args = this.parseArgs();
        // FILTER (...) / OVER (...) on aggregates
        if (this.isWord('filter') && this.isPunct('(', 1)) {
          this.i++;
          this.skipBalanced('(', ')');
        }
        if (this.isWord('over')) {
          this.i++;
          if (this.isPunct('(')) this.skipBalanced('(', ')');
          else this.i++;
        }
        return { k: 'func', name: parts.join('.'), args };
      }
      return { k: 'col', parts };
    }
    throw new ParseError(`unexpected token ${t.value}`);
  }
  parseCase(): Expr {
    // CASE is folded only by the evaluator's "unknown"; we just need to consume it.
    this.i++;
    let depth = 1;
    while (depth > 0) {
      const t = this.peek();
      if (!t) throw new ParseError('case');
      if (t.type === 'word' && t.value === 'case') depth++;
      if (t.type === 'word' && t.value === 'end') depth--;
      this.i++;
    }
    return { k: 'opaque' };
  }
  /** `select <target> [from ...] [where ...] [...]` up to the closing paren (not consumed). */
  parseSelectBody(): SubSelect {
    if (this.isWord('with')) {
      this.skipToParenEnd();
      return { target: null, from: [], where: null, simpleFrom: false };
    }
    this.i++; // select
    this.eatWord('distinct');
    let target: Expr | null = null;
    try {
      const save = this.i;
      target = this.parseOr();
      if (this.eatWord('as')) this.i++;
      if (this.isPunct(',')) {
        this.i = save;
        target = null;
        this.skipUntilWords(['from', 'where']);
      }
    } catch {
      target = null;
      this.skipUntilWords(['from', 'where']);
    }
    const from: FromItem[] = [];
    let simpleFrom = true;
    if (this.eatWord('from')) {
      for (;;) {
        const first = identValue(this.peek());
        if (!first || this.isPunct('(', 1)) {
          simpleFrom = false;
          break;
        }
        const name = [first];
        this.i++;
        while (this.isPunct('.') && identValue(this.peek(1))) {
          name.push(identValue(this.peek(1))!);
          this.i += 2;
        }
        let alias: string | undefined;
        if (this.eatWord('as')) {
          alias = identValue(this.peek()) ?? undefined;
          this.i++;
        } else {
          const a = this.peek();
          if (a && (a.type === 'qident' || (a.type === 'word' && !STOP_WORDS.has(a.value)))) {
            alias = a.value;
            this.i++;
          }
        }
        from.push({ name, alias });
        if (this.isPunct(',')) {
          this.i++;
          continue;
        }
        break;
      }
      if (!this.isWord('where') && !this.isPunct(')') && !this.done()) {
        simpleFrom = false;
        this.skipUntilWords(['where']);
      }
    }
    let where: Expr | null = null;
    if (this.eatWord('where')) {
      try {
        where = this.parseOr();
      } catch {
        where = null;
      }
    }
    this.skipToParenEnd();
    return { target, from, where, simpleFrom };
  }
  skipUntilWords(words: string[]): void {
    while (!this.done() && !this.isPunct(')')) {
      if (words.some((w) => this.isWord(w))) return;
      if (this.isPunct('(')) this.skipBalanced('(', ')');
      else this.i++;
    }
  }
  skipToParenEnd(): void {
    while (!this.done() && !this.isPunct(')')) {
      if (this.isPunct('(')) this.skipBalanced('(', ')');
      else this.i++;
    }
  }
}

/** Parse a policy expression; `null` when it cannot be parsed (treated as restrictive). */
export function parseExpr(tokens: Token[]): Expr | null {
  if (tokens.length === 0) return null;
  try {
    const p = new Parser(tokens);
    const e = p.parseOr();
    return p.done() ? e : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- evaluation

export type Role = 'anon' | 'authenticated';

/** Abstract value. `opaque` is a value we cannot know; `nonnull` says whether it is surely non-null. */
type V =
  | { k: 'bool'; v: boolean }
  | { k: 'null' }
  | { k: 'str'; v: string }
  | { k: 'num'; v: number }
  | { k: 'opaque'; nonnull: boolean; sig?: string };

const UNKNOWN: V = { k: 'opaque', nonnull: false };
const T: V = { k: 'bool', v: true };
const F: V = { k: 'bool', v: false };

/** Column resolver for subqueries: does `table` (qualified parts) have column `col`? `null` = not known. */
export type ColumnLookup = (table: string[], col: string) => boolean | null;

export interface EvalContext {
  role: Role;
  columns?: ColumnLookup;
}

function isAuthFn(name: string, fn: string): boolean {
  return name === `auth.${fn}` || name === fn;
}

/** Structural signature for "same expression on both sides" checks; null if it involves unknown values. */
function sig(e: Expr): string | null {
  switch (e.k) {
    case 'col':
      return `col:${e.parts[e.parts.length - 1]}:${e.parts.join('.')}`;
    case 'func':
      return `fn:${e.name}(${e.args.map(sig).join(',')})`;
    case 'cast':
      return sig(e.e);
    case 'const':
      return `c:${String(e.v)}`;
    case 'sub':
      return !e.exists && e.sel.from.length === 0 && e.sel.target ? sig(e.sel.target) : null;
    default:
      return null;
  }
}

function and3(vals: V[]): V {
  let unknown = false;
  for (const v of vals) {
    if (v.k === 'bool' && !v.v) return F;
    if (!(v.k === 'bool' && v.v)) unknown = true;
  }
  return unknown ? UNKNOWN : T;
}
function or3(vals: V[]): V {
  let unknown = false;
  for (const v of vals) {
    if (v.k === 'bool' && v.v) return T;
    if (!(v.k === 'bool' && !v.v)) unknown = true;
  }
  return unknown ? UNKNOWN : F;
}

function constCompare(op: string, a: V, b: V): V {
  if (a.k === 'null' || b.k === 'null') return { k: 'null' };
  let x: string | number | boolean;
  let y: string | number | boolean;
  if (a.k === 'num' && b.k === 'num') {
    x = a.v;
    y = b.v;
  } else if (a.k === 'str' && b.k === 'str') {
    x = a.v;
    y = b.v;
  } else if (a.k === 'bool' && b.k === 'bool') {
    x = a.v ? 1 : 0;
    y = b.v ? 1 : 0;
  } else if ((a.k === 'num' && b.k === 'str') || (a.k === 'str' && b.k === 'num')) {
    // '1' = 1: Postgres coerces the unknown-typed literal
    const na = Number(a.v);
    const nb = Number(b.v);
    if (Number.isNaN(na) || Number.isNaN(nb)) return UNKNOWN;
    x = na;
    y = nb;
  } else if ((a.k === 'bool' && b.k === 'str') || (a.k === 'str' && b.k === 'bool')) {
    const s = a.k === 'str' ? toBool(a.v) : null;
    const t = b.k === 'str' ? toBool(b.v) : null;
    const ba = a.k === 'bool' ? a.v : s;
    const bb = b.k === 'bool' ? b.v : t;
    if (ba === null || bb === null) return UNKNOWN;
    x = ba ? 1 : 0;
    y = bb ? 1 : 0;
  } else return UNKNOWN;
  switch (op) {
    case '=':
      return { k: 'bool', v: x === y };
    case '<>':
      return { k: 'bool', v: x !== y };
    case '<':
      return { k: 'bool', v: x < y };
    case '>':
      return { k: 'bool', v: x > y };
    case '<=':
      return { k: 'bool', v: x <= y };
    case '>=':
      return { k: 'bool', v: x >= y };
    default:
      return UNKNOWN;
  }
}

function toBool(s: string): boolean | null {
  const v = s.trim().toLowerCase();
  if (['t', 'true', 'y', 'yes', 'on', '1'].includes(v)) return true;
  if (['f', 'false', 'n', 'no', 'off', '0'].includes(v)) return false;
  return null;
}

function isConst(v: V): boolean {
  return v.k === 'bool' || v.k === 'str' || v.k === 'num' || v.k === 'null';
}

function evalV(e: Expr, ctx: EvalContext): V {
  switch (e.k) {
    case 'const':
      if (e.v === null) return { k: 'null' };
      if (typeof e.v === 'boolean') return { k: 'bool', v: e.v };
      if (typeof e.v === 'number') return { k: 'num', v: e.v };
      return { k: 'str', v: e.v };
    case 'col':
      return UNKNOWN;
    case 'cast': {
      const v = evalV(e.e, ctx);
      const ty = e.type.replace(/^pg_catalog\./, '');
      if ((ty === 'boolean' || ty === 'bool') && v.k === 'str') {
        const b = toBool(v.v);
        return b === null ? UNKNOWN : { k: 'bool', v: b };
      }
      if ((ty === 'boolean' || ty === 'bool') && v.k === 'num') return { k: 'bool', v: v.v !== 0 };
      if (['int', 'integer', 'int4', 'int8', 'bigint', 'smallint', 'numeric', 'float8', 'real'].includes(ty) && v.k === 'str') {
        const n = Number(v.v);
        return Number.isNaN(n) ? UNKNOWN : { k: 'num', v: n };
      }
      if (['text', 'varchar', 'name', 'character varying'].includes(ty) && v.k === 'num') return { k: 'str', v: String(v.v) };
      return v;
    }
    case 'func': {
      const n = e.name.replace(/^pg_catalog\./, '');
      if (isAuthFn(n, 'role') || n === 'current_user' || n === 'current_role' || n === 'session_user' || n === 'user') {
        return { k: 'str', v: ctx.role };
      }
      if (isAuthFn(n, 'uid') || isAuthFn(n, 'email')) {
        return ctx.role === 'anon' ? { k: 'null' } : { k: 'opaque', nonnull: true, sig: `fn:${n}` };
      }
      if (isAuthFn(n, 'jwt')) return { k: 'opaque', nonnull: true, sig: 'jwt' };
      if (n === 'current_setting' && e.args[0]?.k === 'const' && typeof e.args[0].v === 'string') {
        const key = e.args[0].v.toLowerCase();
        if (key === 'request.jwt.claim.role' || key === 'role') return { k: 'str', v: ctx.role };
        if (key === 'request.jwt.claim.sub') return ctx.role === 'anon' ? { k: 'null' } : { k: 'opaque', nonnull: true, sig: 'fn:uid' };
        if (key === 'request.jwt.claims') return { k: 'opaque', nonnull: true, sig: 'jwt' };
        return UNKNOWN;
      }
      if (n === 'coalesce') {
        for (const a of e.args) {
          const v = evalV(a, ctx);
          if (v.k === 'null') continue;
          if (isConst(v) || (v.k === 'opaque' && v.nonnull)) return v;
          return UNKNOWN;
        }
        return { k: 'null' };
      }
      if (n === 'unary-' || n === 'unary+') return UNKNOWN;
      return UNKNOWN;
    }
    case 'bin': {
      const l = evalV(e.l, ctx);
      const r = evalV(e.r, ctx);
      if (e.op === '->>' || e.op === '->') {
        // auth.jwt() ->> 'role' is the role; ->> 'sub' is the user id
        if (l.k === 'opaque' && l.sig === 'jwt' && r.k === 'str') {
          if (r.v === 'role') return { k: 'str', v: ctx.role };
          if (r.v === 'sub') return ctx.role === 'anon' ? { k: 'null' } : { k: 'opaque', nonnull: true, sig: 'fn:uid' };
        }
        return UNKNOWN;
      }
      if (CMP_OPS.has(e.op)) {
        if (l.k === 'null' || r.k === 'null') return { k: 'null' };
        if (isConst(l) && isConst(r)) return constCompare(e.op, l, r);
        const sl = sig(e.l);
        const sr = sig(e.r);
        const same = (sl !== null && sl === sr) || (l.k === 'opaque' && r.k === 'opaque' && l.sig !== undefined && l.sig === r.sig);
        if (same) {
          // x = x is true for every non-null x (and every row with a non-null column)
          if (e.op === '=' || e.op === '<=' || e.op === '>=') return T;
          if (e.op === '<>' || e.op === '<' || e.op === '>') return F;
        }
        return UNKNOWN;
      }
      if (e.op === 'like' && l.k === 'str' && r.k === 'str') {
        if (r.v === '%') return T;
        return UNKNOWN;
      }
      if (e.op === '||' && l.k === 'str' && r.k === 'str') return { k: 'str', v: l.v + r.v };
      if (l.k === 'num' && r.k === 'num') {
        switch (e.op) {
          case '+':
            return { k: 'num', v: l.v + r.v };
          case '-':
            return { k: 'num', v: l.v - r.v };
          case '*':
            return { k: 'num', v: l.v * r.v };
          case '/':
            return r.v === 0 ? UNKNOWN : { k: 'num', v: l.v / r.v };
          default:
            return UNKNOWN;
        }
      }
      return UNKNOWN;
    }
    case 'and':
      return and3(e.args.map((a) => evalV(a, ctx)));
    case 'or':
      return or3(e.args.map((a) => evalV(a, ctx)));
    case 'not': {
      const v = evalV(e.e, ctx);
      if (v.k === 'bool') return { k: 'bool', v: !v.v };
      if (v.k === 'null') return v;
      return UNKNOWN;
    }
    case 'is': {
      const v = evalV(e.e, ctx);
      let res: V;
      if (e.test === 'null') {
        if (v.k === 'null') res = T;
        else if (isConst(v) || (v.k === 'opaque' && v.nonnull)) res = F;
        else res = UNKNOWN;
      } else if (e.test === 'true' || e.test === 'false') {
        const want = e.test === 'true';
        if (v.k === 'bool') res = { k: 'bool', v: v.v === want };
        else if (v.k === 'null') res = F;
        else res = UNKNOWN;
      } else if (e.test === 'unknown') {
        res = v.k === 'null' ? T : v.k === 'bool' ? F : UNKNOWN;
      } else {
        const r = evalV(e.r!, ctx);
        const sl = sig(e.e);
        if (sl !== null && sl === sig(e.r!)) res = F; // x is distinct from x: always false
        else if (v.k === 'null' || r.k === 'null') res = isConst(v) && isConst(r) ? { k: 'bool', v: v.k !== r.k } : UNKNOWN;
        else if (isConst(v) && isConst(r)) {
          const eq = constCompare('=', v, r);
          res = eq.k === 'bool' ? { k: 'bool', v: !eq.v } : UNKNOWN;
        } else res = UNKNOWN;
      }
      if (e.neg && res.k === 'bool') return { k: 'bool', v: !res.v };
      return e.neg ? UNKNOWN : res;
    }
    case 'in': {
      if (e.list === null) return UNKNOWN;
      const v = evalV(e.e, ctx);
      if (!isConst(v) || v.k === 'null') return v.k === 'null' ? { k: 'null' } : UNKNOWN;
      let any = false;
      let unknown = false;
      for (const item of e.list) {
        const iv = evalV(item, ctx);
        const c = isConst(iv) ? constCompare('=', v, iv) : UNKNOWN;
        if (c.k === 'bool' && c.v) any = true;
        else if (!(c.k === 'bool')) unknown = true;
      }
      const res: V = any ? T : unknown ? UNKNOWN : F;
      if (e.neg && res.k === 'bool') return { k: 'bool', v: !res.v };
      return e.neg ? UNKNOWN : res;
    }
    case 'sub': {
      // (select auth.uid()) and other FROM-less scalar subqueries evaluate to their target
      if (e.sel.from.length === 0 && e.sel.simpleFrom && e.sel.target) {
        const v = evalV(e.sel.target, ctx);
        if (e.exists) return T;
        if (e.sel.where) {
          const w = evalV(e.sel.where, ctx);
          if (!(w.k === 'bool' && w.v)) return UNKNOWN;
        }
        return v;
      }
      return UNKNOWN;
    }
    case 'opaque':
      return UNKNOWN;
  }
}

/** Is the expression TRUE for every row when evaluated for `role`? */
export function alwaysTrueFor(e: Expr | null, ctx: EvalContext): boolean {
  if (!e) return false;
  const v = evalV(e, ctx);
  return v.k === 'bool' && v.v;
}

export interface SelfCompare {
  /** Rendered column, e.g. `m.org_id = org_id`. */
  text: string;
  column: string;
}

/**
 * Find `inner.col = col` comparisons inside subqueries where the unqualified side resolves to the
 * subquery's own table (it has that column), so the "join" to the outer row compares a column
 * with itself. Classic multi-tenant bug: `exists (select 1 from members m where m.user_id =
 * auth.uid() and m.org_id = org_id)` is true for every row once the user is in any org.
 */
export function findSelfCompares(e: Expr | null, columns: ColumnLookup): SelfCompare[] {
  const out: SelfCompare[] = [];
  const visit = (x: Expr | null | undefined, sub?: SubSelect): void => {
    if (!x) return;
    switch (x.k) {
      case 'bin':
        if (sub && x.op === '=' && x.l.k === 'col' && x.r.k === 'col') {
          const a = resolveInner(x.l.parts, sub, columns);
          const b = resolveInner(x.r.parts, sub, columns);
          if (a && b && a === b) out.push({ text: `${x.l.parts.join('.')} = ${x.r.parts.join('.')}`, column: x.l.parts[x.l.parts.length - 1]! });
        }
        visit(x.l, sub);
        visit(x.r, sub);
        return;
      case 'and':
      case 'or':
        x.args.forEach((a) => visit(a, sub));
        return;
      case 'not':
        visit(x.e, sub);
        return;
      case 'is':
        visit(x.e, sub);
        visit(x.r, sub);
        return;
      case 'cast':
        visit(x.e, sub);
        return;
      case 'func':
        x.args.forEach((a) => visit(a, sub));
        return;
      case 'in':
        visit(x.e, sub);
        x.list?.forEach((a) => visit(a, sub));
        if (x.sub) visit(x.sub.where, x.sub);
        return;
      case 'sub':
        visit(x.sel.where, x.sel);
        return;
      default:
        return;
    }
  };
  visit(e);
  return out;
}

/** Which FROM item of `sub` a column reference binds to (alias or table name key), or null for the outer query. */
function resolveInner(parts: string[], sub: SubSelect, columns: ColumnLookup): string | null {
  if (!sub.simpleFrom || sub.from.length === 0) return null;
  const col = parts[parts.length - 1]!;
  if (parts.length >= 2) {
    const q = parts[parts.length - 2]!;
    const hit = sub.from.find((f) => (f.alias ?? f.name[f.name.length - 1]) === q || (!f.alias && f.name[f.name.length - 1] === q));
    return hit ? `${hit.alias ?? hit.name.join('.')}.${col}` : null;
  }
  for (const f of sub.from) {
    const has = columns(f.name, col);
    if (has === null) return null; // inner columns unknown: cannot tell
    if (has) return `${f.alias ?? f.name.join('.')}.${col}`;
  }
  return null;
}

/** Compact rendering of an expression for messages (first ~80 chars of the source). */
export function renderTokens(tokens: Token[], source: string): string {
  if (tokens.length === 0) return '';
  const text = source.slice(tokens[0]!.start, tokens[tokens.length - 1]!.end).replace(/\s+/g, ' ').trim();
  return text.length > 80 ? `${text.slice(0, 77)}...` : text;
}
