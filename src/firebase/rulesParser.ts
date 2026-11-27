/**
 * Tolerant scanner for the Firebase security rules language (firestore.rules,
 * storage.rules). It is not a full parser: it recovers `match` nesting, `allow`
 * statements (methods + condition + line) and simple `function ... return` bodies,
 * and ignores everything else. Unknown syntax never throws.
 */

export interface AllowStatement {
  /** Methods as written: read, write, get, list, create, update, delete. */
  methods: string[];
  /** Condition after `if`, whitespace-squished; undefined for `allow read;`. */
  condition?: string;
  /** 1-based line of the `allow` keyword. */
  line: number;
  /** The statement, squished to one line (NOT yet redacted). */
  text: string;
  /** Concatenated match path, e.g. /databases/{database}/documents/users/{userId}. */
  path: string;
  /** True when the innermost match is a recursive wildcard such as {document=**}. */
  recursive: boolean;
}

export interface ParsedRules {
  service: 'firestore' | 'storage' | 'unknown';
  allows: AllowStatement[];
  /** Simple one-expression helper functions, by name. */
  functions: Map<string, string>;
}

/** Replace comments with spaces (newlines kept so line numbers survive); strings are left alone. */
export function stripComments(src: string): string {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    const n = src[i + 1];
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      out += src.slice(i, j + 1);
      i = j + 1;
    } else if (c === '/' && n === '/') {
      while (i < src.length && src[i] !== '\n') {
        out += ' ';
        i++;
      }
    } else if (c === '/' && n === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end < 0 ? src.length : end + 2;
      out += src.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

const squish = (s: string): string => s.replace(/\s+/g, ' ').trim();

interface Frame {
  match: boolean;
  path: string;
  recursive: boolean;
}

export function parseRules(source: string): ParsedRules {
  const src = stripComments(source);
  const service = /service\s+cloud\.firestore\b/.test(src)
    ? 'firestore'
    : /service\s+firebase\.storage\b/.test(src)
      ? 'storage'
      : 'unknown';
  const functions = new Map<string, string>();
  const fnRe = /\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*\{\s*(?:let\s+[^;]*;\s*)*return\s+([^;]+);\s*\}/g;
  for (const m of src.matchAll(fnRe)) functions.set(m[1]!, squish(m[2]!));

  const allows: AllowStatement[] = [];
  const stack: Frame[] = [];
  let stmt = '';
  let stmtLine = 1;
  let depth = 0; // ( and [ nesting: braces and semicolons inside are not structural
  let line = 1;

  const handle = (): void => {
    const text = squish(stmt);
    stmt = '';
    if (!/^allow\b/.test(text)) return;
    const m = /^allow\s+([^:]*?)\s*(?::\s*(?:if\s+(.*))?)?$/.exec(text);
    if (!m) return;
    const methods = m[1]!
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    if (methods.length === 0) return;
    const matches = stack.filter((f) => f.match);
    allows.push({
      methods,
      condition: m[2]?.trim() || undefined,
      line: stmtLine,
      text,
      path: matches.map((f) => f.path).join(''),
      recursive: matches.length > 0 && matches[matches.length - 1]!.recursive,
    });
  };

  for (let i = 0; i < src.length; i++) {
    const c = src[i]!;
    if (c === '\n') line++;
    if (!stmt && /\s/.test(c)) continue;
    if (!stmt) stmtLine = line;

    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      stmt += src.slice(i, j + 1);
      i = j;
      continue;
    }
    if (c === '(' || c === '[') depth++;
    else if ((c === ')' || c === ']') && depth > 0) depth--;

    if (depth === 0) {
      if (c === ';') {
        handle();
        continue;
      }
      if (c === '{') {
        const isMatch = /^match\b/.test(stmt);
        // `match /users/{userId} {`: a brace right after a slash is a path wildcard, not a block.
        if (isMatch && /\/\s*$/.test(stmt)) {
          const close = src.indexOf('}', i);
          if (close > 0) {
            stmt += src.slice(i, close + 1);
            i = close;
            continue;
          }
        }
        const path = isMatch ? squish(stmt).replace(/^match\s+/, '').replace(/\s+/g, '') : '';
        stack.push({ match: isMatch, path, recursive: isMatch && /=\*\*\}/.test(path) });
        stmt = '';
        continue;
      }
      if (c === '}') {
        handle();
        stack.pop();
        continue;
      }
    }
    stmt += c;
  }
  return { service, allows, functions };
}

/** Inline calls to simple helper functions (depth-limited) so `isOwner(id)` is analysed by its body. */
export function inlineFunctions(cond: string, fns: Map<string, string>, depth = 0): string {
  if (depth >= 3 || fns.size === 0) return cond;
  return cond.replace(/\b([A-Za-z_]\w*)\s*\(\s*[^()]*\)/g, (whole, name: string) => {
    const body = fns.get(name);
    return body ? `(${inlineFunctions(body, fns, depth + 1)})` : whole;
  });
}

/** Split on a top-level operator (`&&` / `||`), ignoring anything inside parens or strings. */
export function splitTop(expr: string, op: '&&' | '||'): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote = '';
  let last = 0;
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i]!;
    if (quote) {
      if (c === quote) quote = '';
    } else if (c === '"' || c === "'") quote = c;
    else if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (depth === 0 && expr.startsWith(op, i)) {
      parts.push(expr.slice(last, i).trim());
      last = i + 2;
      i++;
    }
  }
  parts.push(expr.slice(last).trim());
  return parts.filter(Boolean);
}

export function stripParens(s: string): string {
  let t = s.trim();
  while (t.startsWith('(') && t.endsWith(')') && splitTop(t.slice(1, -1), '||').length === 1 && balanced(t.slice(1, -1))) {
    t = t.slice(1, -1).trim();
  }
  return t;
}

function balanced(s: string): boolean {
  let d = 0;
  for (const c of s) {
    if (c === '(') d++;
    else if (c === ')' && --d < 0) return false;
  }
  return d === 0;
}
