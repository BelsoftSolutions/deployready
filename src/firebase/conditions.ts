/**
 * Classifies a rules condition by how much it actually restricts access. Shared
 * by the Firestore/Storage rules and Realtime Database rules checks.
 */
import { splitTop, stripParens } from './rulesParser';

export type CondClass =
  | { kind: 'open' }
  | { kind: 'auth' }
  | { kind: 'test-mode'; expires: Date }
  | { kind: 'other' };

const SIGNED_IN: RegExp[] = [
  /^request\.auth\s*!=\s*null$/,
  /^request\.auth\.uid\s*!=\s*null$/,
  /^auth\s*!=\s*null$/,
  /^auth\.uid\s*!=\s*null$/,
  /^request\.auth\.token\.email_verified\s*==\s*true$/,
  /^(?:is)?(?:signed|logged)_?in\(\s*\)$/i,
  /^is_?(?:signed|logged)_?in\(\s*\)$/i,
  /^is_?authenticated\(\s*\)$/i,
  /^authenticated\(\s*\)$/i,
];

const TEST_MODE_RE = /^request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)$/;
const RTDB_TEST_MODE_RE = /^now\s*<\s*(\d{10,13})$/;

type Atom = 'open' | 'auth' | { expires: Date } | 'other';

function atom(raw: string): Atom {
  const t = stripParens(raw).replace(/\s+/g, ' ');
  if (t === 'true') return 'open';
  if (SIGNED_IN.some((re) => re.test(t))) return 'auth';
  const m = TEST_MODE_RE.exec(t);
  if (m) return { expires: new Date(Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!)) };
  const r = RTDB_TEST_MODE_RE.exec(t);
  if (r) return { expires: new Date(r[1]!.length <= 10 ? +r[1]! * 1000 : +r[1]!) };
  return 'other';
}

/** `resolved` is the condition with simple helper functions already inlined. */
export function classifyCondition(resolved: string | undefined): CondClass {
  if (resolved === undefined || resolved.trim() === '') return { kind: 'open' };
  const alts = splitTop(stripParens(resolved), '||').map((alt) => splitTop(stripParens(alt), '&&').map(atom));
  const classes = alts.map((parts): CondClass => {
    if (parts.every((p) => p === 'open')) return { kind: 'open' };
    const time = parts.find((p): p is { expires: Date } => typeof p === 'object');
    if (time && parts.every((p) => p === 'open' || typeof p === 'object')) return { kind: 'test-mode', expires: time.expires };
    if (parts.every((p) => p === 'open' || p === 'auth')) return { kind: 'auth' };
    return { kind: 'other' };
  });
  const open = classes.find((c) => c.kind === 'open');
  if (open) return open;
  const test = classes.find((c) => c.kind === 'test-mode');
  if (test && classes.every((c) => c.kind === 'test-mode' || c.kind === 'auth')) return test;
  if (classes.every((c) => c.kind === 'auth')) return { kind: 'auth' };
  return { kind: 'other' };
}
