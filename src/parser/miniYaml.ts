/**
 * A deliberately small reader for block-style YAML (enough for OpenAPI files).
 * Maps and sequences by indentation, plain/quoted scalars (kept as strings),
 * block scalars (`|`, `>`) skipped. Flow collections (`{a: 1}`, `[a, b]`) are
 * kept as opaque `YamlFlow` values, except the empty `{}` / `[]`. Anything it
 * cannot read faithfully (anchors, aliases, tags, merge keys, complex keys,
 * several documents, multi-line quoted scalars, tabs) throws `YamlUnsupported`
 * so the caller can skip the file instead of guessing.
 */

export class YamlUnsupported extends Error {}

/** A flow-style collection that was not interpreted. */
export class YamlFlow {
  constructor(public readonly raw: string) {}
}

export type YamlValue = string | YamlValue[] | YamlMap | YamlFlow;
export interface YamlMap {
  [key: string]: YamlValue;
}

interface Line {
  indent: number;
  text: string;
}

const MAX_LINES = 200000;

export function parseYaml(source: string): YamlValue {
  const raw = source.replace(/^﻿/, '').split(/\r?\n/);
  if (raw.length > MAX_LINES) throw new YamlUnsupported('file has too many lines');
  const lines: Line[] = [];
  let sawContent = false;
  for (const r of raw) {
    const trimmed = r.trim();
    if (trimmed === '' || trimmed.startsWith('#')) {
      lines.push({ indent: -1, text: r });
      continue;
    }
    if (/^\t/.test(r) || /^ *\t/.test(r)) throw new YamlUnsupported('tab indentation');
    if (!sawContent && trimmed.startsWith('%')) continue;
    if (trimmed === '---' || trimmed.startsWith('--- ')) {
      if (sawContent) throw new YamlUnsupported('multiple YAML documents');
      sawContent = true;
      const rest = trimmed.slice(3).trim();
      if (rest && !rest.startsWith('#')) lines.push({ indent: 0, text: rest });
      continue;
    }
    if (trimmed === '...') throw new YamlUnsupported('document end marker');
    sawContent = true;
    lines.push({ indent: r.length - r.trimStart().length, text: r });
  }
  return new Reader(lines).document();
}

class Reader {
  private i = 0;
  constructor(private readonly lines: Line[]) {}

  document(): YamlValue {
    const first = this.peek();
    if (!first) return '';
    const value = this.block(first.indent);
    if (this.peek()) throw new YamlUnsupported('unexpected indentation');
    return value;
  }

  /** Next line that carries content (skips blank and comment lines). */
  private peek(): Line | null {
    while (this.i < this.lines.length && this.lines[this.i]!.indent < 0) this.i++;
    return this.i < this.lines.length ? this.lines[this.i]! : null;
  }

  private content(line: Line): string {
    return stripComment(line.text.trim());
  }

  private block(indent: number): YamlValue {
    const line = this.peek();
    if (!line || line.indent < indent) return '';
    const text = this.content(line);
    if (isSeqItem(text)) return this.sequence(line.indent);
    if (keySplit(text)) return this.mapping(line.indent);
    if (text.startsWith('{') || text.startsWith('[')) {
      this.i++;
      return this.flowValue(text);
    }
    this.i++;
    return this.scalar(text, line.indent - 1);
  }

  private mapping(indent: number): YamlValue {
    const map: YamlMap = Object.create(null) as YamlMap;
    for (;;) {
      const line = this.peek();
      if (!line || line.indent < indent) break;
      if (line.indent > indent) throw new YamlUnsupported('unexpected indentation');
      const text = this.content(line);
      if (isSeqItem(text)) break;
      const kv = keySplit(text);
      if (!kv) throw new YamlUnsupported('expected a "key: value" line');
      if (kv.key === '<<') throw new YamlUnsupported('merge key');
      this.i++;
      map[kv.key] = this.value(kv.rest, indent);
    }
    return map;
  }

  private sequence(indent: number): YamlValue {
    const out: YamlValue[] = [];
    for (;;) {
      const line = this.peek();
      if (!line || line.indent < indent) break;
      if (line.indent > indent) throw new YamlUnsupported('unexpected indentation');
      const text = this.content(line);
      if (!isSeqItem(text)) break;
      const rest = text.slice(1).replace(/^\s+/, '');
      const offset = line.text.length - line.text.trimStart().length + (text.length - rest.length);
      if (rest === '') {
        this.i++;
        const next = this.peek();
        out.push(next && next.indent > indent ? this.block(next.indent) : '');
        continue;
      }
      // Re-read the item content as if it were its own line at the item's column.
      this.lines[this.i] = { indent: offset, text: ' '.repeat(offset) + rest };
      out.push(this.block(offset));
    }
    return out;
  }

  /** The value after `key:` (rest) for a key at `indent`; the key's line is already consumed. */
  private value(rest: string, indent: number): YamlValue {
    if (rest === '') {
      const next = this.peek();
      if (next && next.indent > indent) return this.block(next.indent);
      if (next && next.indent === indent && isSeqItem(this.content(next))) return this.sequence(indent);
      return '';
    }
    if (/^[|>](?:[+-]?\d?|\d[+-])$/.test(rest)) {
      this.skipDeeper(indent);
      return '';
    }
    if (rest.startsWith('{') || rest.startsWith('[')) return this.flowValue(rest);
    return this.scalar(rest, indent);
  }

  private flowValue(first: string): YamlValue {
    let text = first;
    let depth = bracketDepth(text);
    while (depth > 0) {
      if (this.i >= this.lines.length) throw new YamlUnsupported('unterminated flow collection');
      const line = this.lines[this.i++]!;
      if (line.indent < 0) continue;
      const more = stripComment(line.text.trim());
      text += ` ${more}`;
      depth = bracketDepth(text);
    }
    if (depth < 0) throw new YamlUnsupported('unbalanced flow collection');
    const compact = text.replace(/\s+/g, '');
    if (compact === '{}') return Object.create(null) as YamlMap;
    if (compact === '[]') return [];
    return new YamlFlow(text);
  }

  /** A scalar value; plain scalars may continue on deeper-indented lines. */
  private scalar(rest: string, indent: number): string {
    const c = rest[0]!;
    if (c === '&' || c === '*' || c === '!') throw new YamlUnsupported('anchor, alias or tag');
    if (c === '"' || c === "'") {
      const end = closingQuote(rest);
      if (end < 0) throw new YamlUnsupported('multi-line quoted scalar');
      if (rest.slice(end + 1).trim() !== '') throw new YamlUnsupported('text after quoted scalar');
      return unquote(rest.slice(0, end + 1));
    }
    let value = rest;
    for (;;) {
      const next = this.peek();
      if (!next || next.indent <= indent) break;
      value += ` ${this.content(next)}`;
      this.i++;
    }
    return value;
  }

  private skipDeeper(indent: number): void {
    while (this.i < this.lines.length) {
      const l = this.lines[this.i]!;
      if (l.indent >= 0 && l.indent <= indent) break;
      this.i++;
    }
  }
}

function isSeqItem(text: string): boolean {
  return text === '-' || text.startsWith('- ');
}

function bracketDepth(text: string): number {
  let depth = 0;
  let quote = '';
  for (let k = 0; k < text.length; k++) {
    const ch = text[k]!;
    if (quote) {
      if (ch === '\\' && quote === '"') k++;
      else if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '{' || ch === '[') depth++;
    else if (ch === '}' || ch === ']') depth--;
  }
  return depth;
}

/** Index of the quote that closes the one opening `s`, or -1. */
function closingQuote(s: string): number {
  const q = s[0]!;
  for (let k = 1; k < s.length; k++) {
    const ch = s[k]!;
    if (q === '"' && ch === '\\') k++;
    else if (ch === q) {
      if (q === "'" && s[k + 1] === "'") k++;
      else return k;
    }
  }
  return -1;
}

function unquote(q: string): string {
  const inner = q.slice(1, -1);
  if (q[0] === "'") return inner.replace(/''/g, "'");
  return inner.replace(/\\(["\\/])/g, '$1').replace(/\\n/g, '\n').replace(/\\t/g, '\t');
}

/** Split `key: rest` (key plain or quoted). Null when the text is not a mapping entry. */
function keySplit(text: string): { key: string; rest: string } | null {
  const c = text[0];
  if (!c) return null;
  if (c === '{' || c === '[') return null;
  if (c === '&' || c === '*' || c === '!') throw new YamlUnsupported('anchor, alias or tag');
  if (c === '?' && (text === '?' || text[1] === ' ')) throw new YamlUnsupported('complex key');
  if (c === '"' || c === "'") {
    const end = closingQuote(text);
    if (end < 0) return null;
    const after = text.slice(end + 1);
    const m = /^\s*:(\s+(.*))?$/.exec(after);
    if (!m) return null;
    return { key: unquote(text.slice(0, end + 1)), rest: (m[2] ?? '').trim() };
  }
  const m = /^(.*?):(?:\s+(.*))?$/.exec(text);
  if (!m) return null;
  return { key: m[1]!.trim(), rest: (m[2] ?? '').trim() };
}

/** Drop a trailing ` # comment` that is outside quotes. */
function stripComment(text: string): string {
  let quote = '';
  for (let k = 0; k < text.length; k++) {
    const ch = text[k]!;
    if (quote) {
      if (ch === '\\' && quote === '"') k++;
      else if (ch === quote) quote = '';
      continue;
    }
    const prev = k === 0 ? ' ' : text[k - 1]!;
    if ((ch === '"' || ch === "'") && /[\s:,[{-]/.test(prev)) quote = ch;
    else if (ch === '#' && /\s/.test(prev)) return text.slice(0, k).trimEnd();
  }
  return text;
}
