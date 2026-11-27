/**
 * Multi-line secrets: PEM / OpenSSH / PGP private key blocks, either across real lines or
 * escaped on one line (`"-----BEGIN PRIVATE KEY-----\nMIIE…\n-----END PRIVATE KEY-----\n"`,
 * as in a GCP service-account JSON). Redaction keeps the line count so numbered output
 * (MCP get_finding, reports) still lines up.
 */

const BEGIN_RE = /-----BEGIN ((?:[A-Z0-9]{1,20} ){0,3})PRIVATE KEY( BLOCK)?-----/g;
const MAX_BLOCK = 20_000;
/** A PEM body / armor-header line (base64, `Proc-Type:`, escaped `\n`, quotes and joiners). */
const BODY_LINE_RE = /^[\s"'`+,;\\n]*(?:[A-Za-z0-9+/=]{8,}|Proc-Type:[^\n]*|DEK-Info:[^\n]*|Comment:[^\n]*|Version:[^\n]*)?[\s"'`+,;\\n]*$/;
/** A lone PEM-width base64 line (a key body without its header, e.g. a cut snippet). */
const ORPHAN_BODY_RE = /^(\s*["'`]?)([A-Za-z0-9+/]{64})(["'`]?[,;+]?\s*)$/;

export interface Block {
  start: number;
  end: number;
}

/** Offsets of every private-key block in `text` (terminated or not). */
export function privateKeyBlocks(text: string): Block[] {
  const out: Block[] = [];
  BEGIN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = BEGIN_RE.exec(text)) !== null) {
    const start = m.index;
    const footer = `-----END ${m[1] ?? ''}PRIVATE KEY${m[2] ?? ''}-----`;
    // Search only a bounded window so many headers cannot make this quadratic.
    const rel = text.slice(start + m[0].length, start + MAX_BLOCK).indexOf(footer);
    const endIdx = rel < 0 ? -1 : start + m[0].length + rel;
    if (endIdx >= 0) {
      out.push({ start, end: endIdx + footer.length });
      BEGIN_RE.lastIndex = endIdx + footer.length;
      continue;
    }
    // Unterminated (truncated snippet): the rest of the header's line, then following body-like lines.
    let end = text.indexOf('\n', start);
    if (end < 0) end = text.length;
    while (end < text.length && end - start <= MAX_BLOCK) {
      const nextEnd = text.indexOf('\n', end + 1);
      const line = text.slice(end + 1, nextEnd < 0 ? text.length : nextEnd);
      if (!line.trim() || !BODY_LINE_RE.test(line)) break;
      end = nextEnd < 0 ? text.length : nextEnd;
    }
    out.push({ start, end });
    BEGIN_RE.lastIndex = end;
  }
  return out;
}

/** Replace each block with the placeholder on every line it spans (line count preserved). */
export function redactBlocks(text: string, placeholder: string): string {
  const blocks = privateKeyBlocks(text);
  if (blocks.length === 0) return text;
  let out = '';
  let last = 0;
  for (const b of blocks) {
    out += text.slice(last, b.start);
    out += text
      .slice(b.start, b.end)
      .split('\n')
      .map(() => placeholder)
      .join('\n');
    last = b.end;
  }
  return out + text.slice(last);
}

/** Mask a headerless PEM body line (64 base64 chars, mixed case + digit). */
export function redactOrphanBody(line: string, placeholder: string): string {
  const m = ORPHAN_BODY_RE.exec(line);
  if (!m) return line;
  const body = m[2] ?? '';
  if (!/[a-z]/.test(body) || !/[A-Z]/.test(body) || !/\d/.test(body)) return line;
  return `${m[1]}${placeholder}${m[3]}`;
}
