/** Tolerant JSON reader for database.rules.json (comments and trailing commas allowed) that keeps line numbers. */

export type JNode =
  | { t: 'obj'; entries: { key: string; line: number; val: JNode }[]; line: number }
  | { t: 'str'; v: string; line: number }
  | { t: 'lit'; v: string; line: number };

export function parseJsonLoose(src: string): JNode | undefined {
  let i = 0;
  let line = 1;
  const fail = (): never => {
    throw new Error('parse');
  };
  const ws = (): void => {
    for (;;) {
      const c = src[i];
      if (c === '\n') line++;
      if (c === ' ' || c === '\t' || c === '\r' || c === '\n') i++;
      else if (c === '/' && src[i + 1] === '/') while (i < src.length && src[i] !== '\n') i++;
      else if (c === '/' && src[i + 1] === '*') {
        const end = src.indexOf('*/', i + 2);
        const stop = end < 0 ? src.length : end + 2;
        line += (src.slice(i, stop).match(/\n/g) ?? []).length;
        i = stop;
      } else return;
    }
  };
  const str = (): string => {
    const q = src[i++];
    let out = '';
    while (i < src.length && src[i] !== q) {
      if (src[i] === '\\') {
        out += src[i + 1] ?? '';
        i += 2;
      } else {
        if (src[i] === '\n') fail();
        out += src[i++];
      }
    }
    if (src[i] !== q) fail();
    i++;
    return out;
  };
  const val = (depth: number): JNode => {
    if (depth > 64) fail();
    ws();
    const startLine = line;
    const c = src[i];
    if (c === '{') {
      i++;
      const entries: { key: string; line: number; val: JNode }[] = [];
      for (;;) {
        ws();
        if (src[i] === '}') {
          i++;
          return { t: 'obj', entries, line: startLine };
        }
        if (src[i] !== '"' && src[i] !== "'") fail();
        const keyLine = line;
        const key = str();
        ws();
        if (src[i++] !== ':') fail();
        entries.push({ key, line: keyLine, val: val(depth + 1) });
        ws();
        if (src[i] === ',') i++;
        else if (src[i] !== '}') fail();
      }
    }
    if (c === '"' || c === "'") return { t: 'str', v: str(), line: startLine };
    const m = /^[A-Za-z0-9.+-]+/.exec(src.slice(i, i + 64));
    if (!m) return fail();
    i += m[0].length;
    return { t: 'lit', v: m[0], line: startLine };
  };
  try {
    const node = val(0);
    return node;
  } catch {
    return undefined;
  }
}
