/**
 * Tolerant PostgreSQL lexer + statement splitter.
 *
 * Handles what Supabase migrations actually contain: `--` and nested block comments,
 * '' / E'' strings, dollar quoting ($$ / $tag$), "quoted" identifiers ("" escapes),
 * `::` casts, multi-char operators, and SQL-standard `BEGIN ATOMIC ... END` bodies
 * (whose inner semicolons do not end the statement). It never throws: unknown
 * characters become single-char operator tokens.
 */

export type TokenType = 'word' | 'qident' | 'string' | 'dollar' | 'number' | 'op' | 'punct' | 'param';

export interface Token {
  type: TokenType;
  /** `word`: lower-cased; `qident`: exact name; `string`/`dollar`: decoded content; others: raw text. */
  value: string;
  start: number;
  end: number;
}

export interface Statement {
  tokens: Token[];
  /** 1-based line of the first token in the source. */
  line: number;
  /** The statement's source text (from its first to its last token). */
  text: string;
}

const OP_CHARS = new Set('+-*/<>=~!@#%^&|`?'.split(''));
const PUNCT = new Set('(),;[].:'.split(''));

function isIdentStart(c: string): boolean {
  return /[A-Za-z_\u0080-￿]/.test(c);
}
function isIdentPart(c: string): boolean {
  return /[A-Za-z0-9_$\u0080-￿]/.test(c);
}

export function tokenize(src: string): Token[] {
  const out: Token[] = [];
  const n = src.length;
  let i = 0;
  while (i < n) {
    const c = src[i]!;
    // whitespace
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v') {
      i++;
      continue;
    }
    // -- line comment
    if (c === '-' && src[i + 1] === '-') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    // /* nested block comment */
    if (c === '/' && src[i + 1] === '*') {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (src[i] === '/' && src[i + 1] === '*') {
          depth++;
          i += 2;
        } else if (src[i] === '*' && src[i + 1] === '/') {
          depth--;
          i += 2;
        } else i++;
      }
      continue;
    }
    const start = i;
    // E'...' (backslash escapes), plus N'', B'', X'' and U&'' prefixes on plain strings
    if (/[eEnNbBxX]/.test(c) && src[i + 1] === "'") {
      const escapes = c === 'e' || c === 'E';
      i++;
      const { value, end } = readQuoted(src, i, "'", escapes);
      out.push({ type: 'string', value, start, end });
      i = end;
      continue;
    }
    if ((c === 'u' || c === 'U') && src[i + 1] === '&' && (src[i + 2] === "'" || src[i + 2] === '"')) {
      const q = src[i + 2]!;
      const { value, end } = readQuoted(src, i + 2, q, false);
      out.push({ type: q === "'" ? 'string' : 'qident', value, start, end });
      i = end;
      continue;
    }
    if (c === "'") {
      const { value, end } = readQuoted(src, i, "'", false);
      out.push({ type: 'string', value, start, end });
      i = end;
      continue;
    }
    if (c === '"') {
      const { value, end } = readQuoted(src, i, '"', false);
      out.push({ type: 'qident', value, start, end });
      i = end;
      continue;
    }
    // $1 parameters and $tag$ dollar quotes
    if (c === '$') {
      if (/[0-9]/.test(src[i + 1] ?? '')) {
        let j = i + 1;
        while (j < n && /[0-9]/.test(src[j]!)) j++;
        out.push({ type: 'param', value: src.slice(i, j), start, end: j });
        i = j;
        continue;
      }
      const m = /^\$([A-Za-z_\u0080-￿][A-Za-z0-9_\u0080-￿]*)?\$/.exec(src.slice(i, i + 80));
      if (m) {
        const tag = m[0];
        const bodyStart = i + tag.length;
        const close = src.indexOf(tag, bodyStart);
        const bodyEnd = close < 0 ? n : close;
        const end = close < 0 ? n : close + tag.length;
        out.push({ type: 'dollar', value: src.slice(bodyStart, bodyEnd), start, end });
        i = end;
        continue;
      }
    }
    if (isIdentStart(c)) {
      let j = i + 1;
      while (j < n && isIdentPart(src[j]!)) j++;
      out.push({ type: 'word', value: src.slice(i, j).toLowerCase(), start, end: j });
      i = j;
      continue;
    }
    if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(src[i + 1] ?? ''))) {
      let j = i;
      while (j < n && /[0-9_]/.test(src[j]!)) j++;
      if (src[j] === '.' && src[j + 1] !== '.') {
        j++;
        while (j < n && /[0-9_]/.test(src[j]!)) j++;
      }
      if ((src[j] === 'e' || src[j] === 'E') && /[-+0-9]/.test(src[j + 1] ?? '')) {
        j += 2;
        while (j < n && /[0-9]/.test(src[j]!)) j++;
      }
      out.push({ type: 'number', value: src.slice(i, j).replace(/_/g, ''), start, end: j });
      i = j;
      continue;
    }
    if (c === ':' && src[i + 1] === ':') {
      out.push({ type: 'op', value: '::', start, end: i + 2 });
      i += 2;
      continue;
    }
    if (PUNCT.has(c)) {
      out.push({ type: 'punct', value: c, start, end: i + 1 });
      i++;
      continue;
    }
    if (OP_CHARS.has(c)) {
      let j = i + 1;
      // Stop before a comment start inside an operator run (`=--x`).
      while (j < n && OP_CHARS.has(src[j]!) && !(src[j] === '-' && src[j + 1] === '-') && !(src[j] === '/' && src[j + 1] === '*')) j++;
      out.push({ type: 'op', value: src.slice(i, j), start, end: j });
      i = j;
      continue;
    }
    out.push({ type: 'op', value: c, start, end: i + 1 });
    i++;
  }
  return out;
}

function readQuoted(src: string, openAt: number, q: string, backslash: boolean): { value: string; end: number } {
  let i = openAt + 1;
  let value = '';
  while (i < src.length) {
    const ch = src[i]!;
    if (backslash && ch === '\\' && i + 1 < src.length) {
      value += src[i + 1];
      i += 2;
      continue;
    }
    if (ch === q) {
      if (src[i + 1] === q) {
        value += q;
        i += 2;
        continue;
      }
      return { value, end: i + 1 };
    }
    value += ch;
    i++;
  }
  return { value, end: src.length };
}

/** Line number (1-based) of every offset, computed lazily. */
export function lineIndex(src: string): (offset: number) => number {
  const starts = [0];
  for (let i = 0; i < src.length; i++) if (src.charCodeAt(i) === 10) starts.push(i + 1);
  return (offset: number) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

/** Split into statements at top-level semicolons (BEGIN ATOMIC bodies stay whole). */
export function splitStatements(src: string, lineBase = 0): Statement[] {
  const toks = tokenize(src);
  const lineOf = lineIndex(src);
  const out: Statement[] = [];
  let cur: Token[] = [];
  let atomicDepth = 0;
  const flush = (): void => {
    if (cur.length > 0) {
      const first = cur[0]!;
      const last = cur[cur.length - 1]!;
      out.push({ tokens: cur, line: lineOf(first.start) + lineBase, text: src.slice(first.start, last.end) });
    }
    cur = [];
  };
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k]!;
    if (t.type === 'word' && t.value === 'atomic' && toks[k - 1]?.type === 'word' && toks[k - 1]!.value === 'begin') atomicDepth++;
    else if (atomicDepth > 0 && t.type === 'word' && t.value === 'case') atomicDepth++;
    else if (atomicDepth > 0 && t.type === 'word' && t.value === 'end') atomicDepth--;
    if (t.type === 'punct' && t.value === ';' && atomicDepth === 0) {
      flush();
      continue;
    }
    cur.push(t);
  }
  flush();
  return out;
}
