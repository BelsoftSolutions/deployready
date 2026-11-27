import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scanFirebaseFiles, scanFirebaseStatic } from '../src/firebase/static';
import { scanFirebaseRules, scanRtdbRules } from '../src/firebase/rules';
import { parseRules, stripComments } from '../src/firebase/rulesParser';

const FS = (body: string): string =>
  `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n${body}\n  }\n}\n`;

describe('firebase/rulesParser', () => {
  it('recovers allow statements with path, line and condition; ignores comments', () => {
    const p = parseRules(
      FS(`    match /users/{userId} {\n      // allow read, write: if true;\n      allow read, write: if request.auth.uid == userId;\n      allow delete;\n    }`),
    );
    expect(p.service).toBe('firestore');
    expect(p.allows).toHaveLength(2);
    expect(p.allows[0]).toMatchObject({ methods: ['read', 'write'], condition: 'request.auth.uid == userId', line: 6 });
    expect(p.allows[0]!.path).toBe('/databases/{database}/documents/users/{userId}');
    expect(p.allows[1]!.condition).toBeUndefined();
  });

  it('does not treat // inside strings as a comment and keeps line numbers', () => {
    const out = stripComments("a 'http://x' // c\nb /* x\ny */ c");
    expect(out).toContain("'http://x'");
    expect(out.split('\n')).toHaveLength(3);
  });

  it('tolerates garbage without throwing', () => {
    expect(() => parseRules('service {{{ allow ;; match } } ((')).not.toThrow();
  });
});

describe('firebase/rules: Firestore and Storage', () => {
  const rulesOf = (src: string, file = 'firestore.rules') => scanFirebaseRules(file, src).map((f) => `${f.rule}:${f.severity}:${f.line}`);

  it('flags allow ... if true and a missing condition as critical', () => {
    expect(rulesOf(FS('    match /a/{id} {\n      allow read, write: if true;\n    }'))).toEqual(['firebase-rules-open:critical:5']);
    expect(rulesOf(FS('    match /a/{id} {\n      allow write;\n    }'))).toEqual(['firebase-rules-open:critical:5']);
  });

  it('flags the test-mode template with its expiry date', () => {
    const f = scanFirebaseRules('firestore.rules', FS('    match /{document=**} {\n      allow read, write: if request.time < timestamp.date(2099, 3, 9);\n    }'));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ rule: 'firebase-rules-test-mode', severity: 'critical', line: 5 });
    expect(f[0]!.title).toContain('open to everyone until 2099-03-09');
  });

  it('downgrades an already expired test-mode rule to a warning', () => {
    const f = scanFirebaseRules('firestore.rules', FS('    match /{d=**} {\n      allow read, write: if request.time < timestamp.date(2020, 1, 1);\n    }'));
    expect(f[0]).toMatchObject({ rule: 'firebase-rules-test-mode', severity: 'warning' });
  });

  it('flags auth-only on user-owned paths: critical for writes, warning for reads', () => {
    const f = scanFirebaseRules(
      'firestore.rules',
      FS('    match /users/{userId} {\n      allow read: if request.auth != null;\n      allow update: if request.auth != null;\n    }'),
    );
    expect(f.map((x) => [x.rule, x.severity])).toEqual([
      ['firebase-rules-auth-only', 'warning'],
      ['firebase-rules-auth-only', 'critical'],
    ]);
    expect(f[0]!.recommendation).toContain('request.auth.uid == userId');
  });

  it('accepts owner comparisons, owner fields and ownership helpers', () => {
    const src = FS(`    function isOwner(id) { return request.auth != null && request.auth.uid == id; }
    match /users/{userId} {
      allow read, write: if isOwner(userId);
    }
    match /orders/{orderId} {
      allow read: if request.auth != null && resource.data.userId == request.auth.uid;
    }`);
    expect(scanFirebaseRules('firestore.rules', src)).toEqual([]);
  });

  it('does not flag auth-only on non-owner collections', () => {
    expect(scanFirebaseRules('firestore.rules', FS('    match /posts/{id} {\n      allow create: if request.auth != null;\n    }'))).toEqual([]);
  });

  it('flags a recursive wildcard that is open or auth-only as critical', () => {
    expect(rulesOf(FS('    match /{document=**} {\n      allow read, write: if true;\n    }'))[0]).toMatch(/^firebase-rules-open:critical/);
    expect(rulesOf(FS('    match /{document=**} {\n      allow read, write: if request.auth != null;\n    }'))[0]).toMatch(/^firebase-rules-recursive-wildcard:critical/);
    expect(rulesOf(FS('    match /{document=**} {\n      allow read: if true;\n    }'))[0]).toMatch(/^firebase-rules-open:critical/);
  });

  it('reports a public read on a specific path as a warning only', () => {
    expect(rulesOf(FS('    match /products/{id} {\n      allow read: if true;\n    }'))).toEqual(['firebase-rules-open-read:warning:5']);
  });

  it('handles storage rules', () => {
    const src = `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read, write: if true;\n    }\n  }\n}\n`;
    const f = scanFirebaseRules('storage.rules', src);
    expect(f).toHaveLength(1);
    expect(f[0]!.title).toContain('Cloud Storage');
  });

  it('redacts evidence', () => {
    const key = 'AIza' + 'a'.repeat(35);
    const f = scanFirebaseRules('firestore.rules', FS(`    match /a/{id} {\n      allow write: if true; // ${key}\n    }`));
    expect(JSON.stringify(f)).not.toContain(key);
  });
});

describe('firebase/rules: Realtime Database', () => {
  const run = (src: string) => scanRtdbRules('database.rules.json', src).map((f) => `${f.rule}:${f.severity}:${f.line}`);

  it('flags true at root and write true on narrow paths as critical', () => {
    expect(run('{\n "rules": {\n  ".read": true,\n  ".write": "true"\n }\n}')).toEqual(['firebase-rtdb-open:critical:3', 'firebase-rtdb-open:critical:4']);
    expect(run('{"rules":{"logs":{".write":true}}}')).toEqual(['firebase-rtdb-open:critical:1']);
  });

  it('treats a narrow public read as a warning', () => {
    expect(run('{"rules":{"public":{".read":true}}}')).toEqual(['firebase-rtdb-open:warning:1']);
  });

  it('flags auth != null only as a warning, and the now< test mode as critical', () => {
    expect(run('{"rules":{"users":{"$uid":{".read":"auth != null"}}}}')).toEqual(['firebase-rtdb-auth-only:warning:1']);
    expect(run('{"rules":{".read":"now < 4102444800000"}}')).toEqual(['firebase-rtdb-test-mode:critical:1']);
  });

  it('accepts owner-scoped rules, comments and trailing commas', () => {
    expect(run('{ // c\n "rules": { "users": { "$uid": { ".read": "auth.uid === $uid", ".write": "auth.uid === $uid", }, }, }, }')).toEqual([]);
  });

  it('ignores malformed JSON', () => {
    expect(run('{ not json')).toEqual([]);
  });
});

describe('firebase/static', () => {
  const KEY = '-----BEGIN PRIVATE KEY-----\\nFAKEFAKEFAKE\\n-----END PRIVATE KEY-----\\n';
  const sa = `{\n  "type": "service_account",\n  "project_id": "p",\n  "private_key": "${KEY}",\n  "client_email": "a@p.iam.gserviceaccount.com"\n}`;

  it('flags a committed service account without printing the key', () => {
    const { findings } = scanFirebaseFiles([{ relPath: 'keys/admin.json', source: sa }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ rule: 'firebase-service-account-committed', severity: 'critical', file: 'keys/admin.json', line: 4 });
    expect(JSON.stringify(findings)).not.toContain('FAKEFAKE');
    expect(JSON.stringify(findings)).not.toContain('BEGIN PRIVATE');
  });

  it('skips git-ignored service accounts and JSON without a private key', () => {
    expect(scanFirebaseFiles([{ relPath: 'admin.json', source: sa }], () => true).findings).toEqual([]);
    expect(scanFirebaseFiles([{ relPath: 'x.json', source: '{"type":"service_account"}' }]).findings).toEqual([]);
  });

  it('does NOT flag the public Firebase web config apiKey', () => {
    const cfg = `export const app = initializeApp({ apiKey: "AIza${'b'.repeat(35)}", authDomain: "x.firebaseapp.com", projectId: "x" });`;
    const res = scanFirebaseFiles([
      { relPath: 'src/firebase.ts', source: cfg },
      { relPath: 'firebase.json', source: '{"firestore":{"rules":"firestore.rules"}}' },
      { relPath: 'firestore.rules', source: FS('    match /users/{u} {\n      allow read, write: if request.auth.uid == u;\n    }') },
    ]);
    expect(res.findings).toEqual([]);
    expect(res.detected).toBe(true);
  });

  it('notes a Firebase project with no rules files (info only)', () => {
    const { findings, notes } = scanFirebaseFiles([{ relPath: 'firebase.json', source: '{"hosting":{"public":"dist"}}' }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ rule: 'firebase-no-rules-file', severity: 'info', note: true });
    expect(notes[0]).toContain('hosting');
  });

  it('reports nothing for a project without Firebase', () => {
    const res = scanFirebaseFiles([{ relPath: 'package.json', source: '{}' }]);
    expect(res).toEqual({ findings: [], detected: false, notes: [] });
  });

  it('walks a directory, honours .gitignore for service accounts and skips node_modules', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fb-'));
    try {
      fs.writeFileSync(path.join(dir, 'firestore.rules'), FS('    match /a/{id} {\n      allow write: if true;\n    }'));
      fs.writeFileSync(path.join(dir, 'ignored.json'), sa);
      fs.writeFileSync(path.join(dir, 'committed.json'), sa);
      fs.writeFileSync(path.join(dir, '.gitignore'), 'ignored.json\n');
      fs.mkdirSync(path.join(dir, 'node_modules'));
      fs.writeFileSync(path.join(dir, 'node_modules', 'x.json'), sa);
      const res = await scanFirebaseStatic(dir);
      expect(res.findings.map((f) => `${f.rule}:${f.file}`).sort()).toEqual([
        'firebase-rules-open:firestore.rules',
        'firebase-service-account-committed:committed.json',
      ]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
