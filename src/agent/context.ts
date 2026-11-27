/**
 * Picks the code an AI fix should see and rewrite.
 *
 * - The REPLACEABLE range is the smallest enclosing unit of the finding's line:
 *   JS/TS: the smallest function/method/arrow (else the top-level statement);
 *   Python: the enclosing def/class block (indentation based); other files: ±15 lines.
 *   A unit larger than MAX_LINES falls back to ±15 lines around the line.
 * - The file's import/require lines come back separately as READ-ONLY context.
 *
 * Line numbers match FileEditor (1-based, BOM stripped, CRLF/LF both split).
 */
import { parse } from '@babel/parser';
import type { ParserPlugin } from '@babel/parser';

export const PARSER_PLUGINS: ParserPlugin[] = [
  'typescript',
  'jsx',
  'decorators-legacy',
  'classProperties',
  'topLevelAwait',
  'importAssertions',
];

export const MAX_LINES = 120;
export const FALLBACK_RADIUS = 15;
const MAX_IMPORT_LINES = 40;
const MAX_IMPORT_LINE_LENGTH = 200;

const JS_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const FUNCTION_TYPES = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
  'ObjectMethod',
  'ClassMethod',
  'ClassPrivateMethod',
]);

export interface FixRange {
  startLine: number;
  endLine: number;
  /** Import/require lines outside the range: shown to the model, never replaced. */
  imports: string[];
}

interface Located {
  type: string;
  loc?: { start: { line: number }; end: { line: number } } | null;
  [key: string]: unknown;
}

/** Choose the range to rewrite for `line` (1-based) in `content`, plus read-only import lines. */
export function extractFixRange(content: string, line: number, ext: string): FixRange {
  const lines = content.replace(/^﻿/, '').split(/\r?\n/);
  const count = lines.length > 0 && lines.at(-1) === '' ? lines.length - 1 : lines.length;
  const target = Math.min(Math.max(1, Math.floor(line) || 1), Math.max(1, count));
  const e = ext.toLowerCase();

  let range: [number, number] | null = null;
  let importLines: number[] = [];

  if (JS_EXT.has(e)) {
    const ast = tryParse(content);
    if (ast) {
      const body = ast.program.body as unknown as Located[];
      range = enclosingJsUnit(body, target);
      importLines = jsImportLines(body);
    } else {
      importLines = regexImportLines(lines, JS_IMPORT_RE);
    }
  } else if (e === '.py') {
    range = pythonBlock(lines, count, target);
    importLines = regexImportLines(lines, PY_IMPORT_RE);
  }

  let [start, end] = range ?? around(target, count);
  if (end - start + 1 > MAX_LINES) [start, end] = around(target, count);

  const imports = importLines
    .filter((n) => n < start || n > end)
    .slice(0, MAX_IMPORT_LINES)
    .map((n) => L(lines, n).slice(0, MAX_IMPORT_LINE_LENGTH));
  return { startLine: start, endLine: end, imports };
}

function around(line: number, count: number): [number, number] {
  return [Math.max(1, line - FALLBACK_RADIUS), Math.min(count, line + FALLBACK_RADIUS)];
}

function tryParse(content: string) {
  try {
    return parse(content.replace(/^﻿/, ''), { sourceType: 'unambiguous', plugins: PARSER_PLUGINS });
  } catch {
    return null;
  }
}

function contains(n: Located, line: number): boolean {
  return Boolean(n.loc && n.loc.start.line <= line && n.loc.end.line >= line);
}

/** Smallest function-like node containing `line`, else the top-level statement containing it. */
function enclosingJsUnit(body: Located[], line: number): [number, number] | null {
  const top = body.find((s) => contains(s, line));
  if (!top) return null;
  let best: Located | null = null;
  const visit = (node: unknown): void => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) return node.forEach(visit);
    const n = node as Located;
    if (typeof n.type !== 'string') return;
    if (n.loc && !contains(n, line)) return;
    if (FUNCTION_TYPES.has(n.type) && n.loc) {
      const size = n.loc.end.line - n.loc.start.line;
      // A one-line function (e.g. an inline `.map(x => x)`) is too little context; keep the larger unit.
      if (size > 0 && (!best || size <= best.loc!.end.line - best.loc!.start.line)) best = n;
    }
    for (const [k, v] of Object.entries(n)) {
      if (k === 'loc' || k.endsWith('Comments')) continue;
      visit(v);
    }
  };
  visit(top);
  const unit: Located = best ?? top;
  return [unit.loc!.start.line, unit.loc!.end.line];
}

/** Line numbers of top-level `import` statements and `require(...)` bindings. */
function jsImportLines(body: Located[]): number[] {
  const out: number[] = [];
  for (const s of body) {
    if (!s.loc) continue;
    const isImport = s.type === 'ImportDeclaration' || s.type === 'TSImportEqualsDeclaration';
    if (isImport || hasTopLevelRequire(s)) {
      for (let n = s.loc.start.line; n <= s.loc.end.line; n++) out.push(n);
    }
  }
  return out;
}

function isRequireCall(x: unknown): boolean {
  const c = x as { type?: string; callee?: { type?: string; name?: string }; object?: unknown } | null;
  if (!c) return false;
  if (c.type === 'CallExpression') return c.callee?.type === 'Identifier' && c.callee.name === 'require';
  if (c.type === 'MemberExpression') return isRequireCall(c.object);
  return false;
}

function hasTopLevelRequire(s: Located): boolean {
  if (s.type === 'VariableDeclaration') {
    return ((s.declarations as { init?: unknown }[]) ?? []).some((d) => isRequireCall(d.init));
  }
  if (s.type === 'ExpressionStatement') return isRequireCall(s.expression);
  return false;
}

const JS_IMPORT_RE = /^(import\s.+|(?:const|let|var)\s.+=\s*require\(.*)$/;
const PY_IMPORT_RE = /^(import\s+\S.*|from\s+\S+\s+import\s.+)$/;

/** Top-level (unindented) import lines found by regex: used for Python and unparseable JS. */
function regexImportLines(lines: string[], re: RegExp): number[] {
  const out: number[] = [];
  lines.forEach((l, i) => {
    if (re.test(l.trimEnd())) out.push(i + 1);
  });
  return out;
}

const PY_DEF_RE = /^(\s*)(?:async\s+def|def|class)\s/;

function indentOf(l: string): number {
  return l.length - l.trimStart().length;
}

/** Innermost enclosing def/class block of `line` (with its decorators), or null at module level. */
function pythonBlock(lines: string[], count: number, line: number): [number, number] | null {
  let ref = line;
  while (ref <= count && !L(lines, ref).trim()) ref++;
  if (ref > count) return null;
  const refIndent = indentOf(L(lines, ref));

  let defLine = 0;
  for (let n = ref; n >= 1; n--) {
    const m = PY_DEF_RE.exec(L(lines, n));
    if (m && (n === ref || (m[1] ?? '').length < refIndent)) {
      defLine = n;
      break;
    }
  }
  if (!defLine) return null;

  const defIndent = indentOf(L(lines, defLine));
  let end = defLine;
  for (let n = defLine + 1; n <= count; n++) {
    const l = L(lines, n);
    if (!l.trim()) continue;
    if (indentOf(l) <= defIndent) break;
    end = n;
  }
  let start = defLine;
  while (start > 1 && L(lines, start - 1).trimStart().startsWith('@') && indentOf(L(lines, start - 1)) === defIndent) start--;
  return line >= start && line <= end ? [start, end] : null;
}

function L(lines: string[], n: number): string {
  return lines[n - 1] ?? '';
}
