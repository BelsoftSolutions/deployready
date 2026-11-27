/** Findings for firestore.rules / storage.rules and database.rules.json. */
import { makeFinding } from '../utils/finding';
import { redact } from '../utils/redact';
import type { Finding, Severity } from '../types';
import { parseRules, inlineFunctions, type AllowStatement } from './rulesParser';
import { classifyCondition } from './conditions';
import { parseJsonLoose, type JNode } from './rtdbParser';

const OWASP = 'A01:2025';
const CWE = 'CWE-284';
const WRITE_METHODS = new Set(['write', 'create', 'update', 'delete']);
const OWNER_COLLECTION_RE =
  /^(?:users?|profiles?|accounts?|customers?|members?|orders?|carts?|messages?|chats?|payments?|invoices?|settings|private|notes|todos|tasks|bookmarks|favorites|uploads|files|documents)$/i;

export function evidence(text: string): string {
  return redact(text).slice(0, 200);
}

function fmt(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** Does the (document-relative) path put a wildcard directly under a user-owned collection? */
export function isUserOwnedPath(fullPath: string): boolean {
  const segs = fullPath
    .replace(/^\/databases\/\{[^}]*\}\/documents/, '')
    .replace(/^\/b\/\{[^}]*\}\/o/, '')
    .split('/')
    .filter(Boolean);
  return segs.some((s, i) => OWNER_COLLECTION_RE.test(s) && /^\{[A-Za-z_]\w*\}$/.test(segs[i + 1] ?? ''));
}

const FS_FIX = `match /users/{userId} {
  allow read, write: if request.auth != null && request.auth.uid == userId;
}
match /posts/{postId} {
  allow read: if true;
  allow create: if request.auth != null && request.resource.data.ownerId == request.auth.uid;
  allow update, delete: if request.auth != null && resource.data.ownerId == request.auth.uid;
}`;
const ST_FIX = `match /users/{userId}/{allPaths=**} {
  allow read, write: if request.auth != null && request.auth.uid == userId;
}`;

export function scanFirebaseRules(relPath: string, source: string): Finding[] {
  const parsed = parseRules(source);
  const storage = parsed.service === 'storage' || (parsed.service === 'unknown' && /storage\.rules$/i.test(relPath));
  const fix = storage ? ST_FIX : FS_FIX;
  const where = storage ? 'Cloud Storage' : 'Firestore';
  const out: Finding[] = [];
  const seen = new Set<string>();

  const add = (a: AllowStatement, rule: string, severity: Severity, title: string, description: string, recommendation: string): void => {
    const key = `${rule}:${a.line}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(
      makeFinding({
        rule,
        title,
        severity,
        category: 'security',
        source: 'static',
        file: relPath,
        line: a.line,
        owasp: OWASP,
        cwe: CWE,
        evidence: evidence(a.text),
        description,
        recommendation,
      }),
    );
  };

  for (const a of parsed.allows) {
    const cond = a.condition === undefined ? undefined : inlineFunctions(a.condition, parsed.functions);
    const cls = classifyCondition(cond);
    const writes = a.methods.some((m) => WRITE_METHODS.has(m));
    const methods = a.methods.join(', ');
    const at = a.path.replace(/^\/databases\/\{[^}]*\}\/documents/, '').replace(/^\/b\/\{[^}]*\}\/o/, '') || '/';

    if (cls.kind === 'test-mode') {
      const expired = cls.expires.getTime() < Date.now();
      add(
        a,
        'firebase-rules-test-mode',
        expired ? 'warning' : 'critical',
        expired
          ? `Test mode rules expired ${fmt(cls.expires)}`
          : `Test mode rules: open to everyone until ${fmt(cls.expires)}`,
        expired
          ? `${where} rules still use the test-mode template (\`request.time < timestamp.date(...)\`). It expired on ${fmt(cls.expires)}, so access is now denied, but anyone who extends the date reopens the whole database. Replace it with real rules.`
          : `${where} rules use the test-mode template: until ${fmt(cls.expires)} anyone on the internet, signed in or not, can ${methods} at ${at}. Test mode rules are meant for the first day of prototyping, not for a deployed app.`,
        `Replace the time-limited rule with per-path rules before deploying, for example:\n${fix}`,
      );
    } else if (cls.kind === 'open') {
      const bare = cond === undefined ? 'has no condition' : 'is `if true`';
      if (writes || a.recursive) {
        add(
          a,
          'firebase-rules-open',
          'critical',
          a.recursive ? `${where} rules open to everyone on a recursive wildcard` : `${where} rules let anyone ${methods}`,
          `\`allow ${methods}\` on ${at} ${bare}, so anyone with your public Firebase config (it ships in every client) can ${methods} ${a.recursive ? 'every document/file under this path' : 'here'} without signing in.`,
          `Require sign-in and ownership instead of an open rule:\n${fix}`,
        );
      } else {
        add(
          a,
          'firebase-rules-open-read',
          'warning',
          `${where} path ${at} is publicly readable`,
          `\`allow ${methods}\` on ${at} ${bare}: anyone can read it without signing in. That is fine for intentionally public content and a data leak for anything else.`,
          `If this data is not meant to be public, require ownership:\n${fix}`,
        );
      }
    } else if (cls.kind === 'auth') {
      if (a.recursive) {
        add(
          a,
          'firebase-rules-recursive-wildcard',
          'critical',
          `${where} recursive wildcard allows any signed-in user`,
          `\`allow ${methods}\` on a recursive wildcard (${at}) only checks that the caller is signed in. Anyone can create an account (or sign in anonymously) and then ${writes ? 'read and modify' : 'read'} every document/file, including other users' data.`,
          `Scope rules to specific paths and check ownership; do not use a catch-all:\n${fix}`,
        );
      } else if (isUserOwnedPath(a.path)) {
        add(
          a,
          'firebase-rules-auth-only',
          writes ? 'critical' : 'warning',
          writes ? `Any signed-in user can write other users' data (${at})` : `Any signed-in user can read other users' data (${at})`,
          `\`allow ${methods}\` on ${at} only checks \`request.auth != null\`. It never compares \`request.auth.uid\` to the path variable or to an owner field on the document, so any signed-in user can ${writes ? 'modify' : 'read'} every other user's records.`,
          `Compare the caller to the owner:\n${fix}`,
        );
      }
    }
  }
  return out;
}

// ---------- Realtime Database ----------

const RTDB_FIX = `{
  "rules": {
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    }
  }
}`;

export function scanRtdbRules(relPath: string, source: string): Finding[] {
  const root = parseJsonLoose(source);
  if (!root || root.t !== 'obj') return [];
  const rules = root.entries.find((e) => e.key === 'rules')?.val;
  if (!rules || rules.t !== 'obj') return [];
  const out: Finding[] = [];

  const add = (rule: string, severity: Severity, line: number, title: string, description: string, ev: string): void => {
    out.push(
      makeFinding({
        rule,
        title,
        severity,
        category: 'security',
        source: 'static',
        file: relPath,
        line,
        owasp: OWASP,
        cwe: CWE,
        evidence: evidence(ev),
        description,
        recommendation: `Scope access to the signed-in owner of each path instead:\n${RTDB_FIX}`,
      }),
    );
  };

  const walk = (node: JNode, path: string[]): void => {
    if (node.t !== 'obj') return;
    for (const e of node.entries) {
      if (e.key === '.read' || e.key === '.write') {
        const raw = e.val.t === 'obj' ? undefined : e.val.v;
        if (raw === undefined) continue;
        const cls = classifyCondition(raw === 'true' ? 'true' : raw);
        const at = '/' + path.join('/');
        const broad = path.length === 0 || path[path.length - 1]!.startsWith('$');
        const op = e.key === '.read' ? 'read' : 'write';
        const ev = `${JSON.stringify(e.key)}: ${e.val.t === 'str' ? JSON.stringify(raw) : raw}`;
        if (cls.kind === 'open' && raw.trim() !== '') {
          const critical = op === 'write' || broad;
          add(
            'firebase-rtdb-open',
            critical ? 'critical' : 'warning',
            e.line,
            critical ? `Realtime Database ${op} open to everyone at ${at}` : `Realtime Database path ${at} is publicly readable`,
            `${e.key} is always true at ${at}${broad ? ' (covers everything below it)' : ''}, so anyone with your public Firebase config can ${op} this data without signing in.`,
            ev,
          );
        } else if (cls.kind === 'test-mode') {
          add(
            'firebase-rtdb-test-mode',
            cls.expires.getTime() < Date.now() ? 'warning' : 'critical',
            e.line,
            `Test mode rules: Realtime Database open to everyone until ${fmt(cls.expires)}`,
            `${e.key} at ${at} only checks \`now\` against a date (the test-mode template), so until ${fmt(cls.expires)} anyone can ${op} it.`,
            ev,
          );
        } else if (cls.kind === 'auth') {
          add(
            'firebase-rtdb-auth-only',
            'warning',
            e.line,
            `Any signed-in user can ${op} ${at}`,
            `${e.key} at ${at} only requires \`auth != null\`. Anyone can create an account, so this does not separate one user's data from another's.`,
            ev,
          );
        }
      } else if (!e.key.startsWith('.')) {
        walk(e.val, [...path, e.key]);
      }
    }
  };
  walk(rules, []);
  return out;
}
