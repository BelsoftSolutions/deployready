import * as path from 'path';
import { scanFirebaseFiles, scanFirebaseStatic } from '../src/firebase/static';
import { buildPlan, planRulesFile } from '../src/firebase/emulator/plan';
import { runPlan, assertLoopback, emulatorToken, type HttpReq, type Op, type Transport } from '../src/firebase/emulator/probe';
import { reconcile } from '../src/firebase/emulator/reconcile';
import { runEmulatorChecks, pickRulesFiles } from '../src/firebase/emulator';
import { parseJavaMajor } from '../src/firebase/emulator/process';
import { firebaseStep } from '../src/firebase';
import { firebaseEmulatorAdapter } from '../src/adapters/firebaseEmulator';

const CORPUS = path.join(__dirname, '..', 'benchmark', 'corpus', 'firebase');
const FS = (body: string): string => `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n${body}\n  }\n}\n`;

type Policy = (uid: string | null, op: Op, docPath: string) => boolean;

/** A tiny stand-in for the emulator's REST surface: the policy decides allow/deny. */
function fakeEmulator(policy: Policy): { transport: Transport; seen: HttpReq[] } {
  const seen: HttpReq[] = [];
  const transport: Transport = async (r) => {
    seen.push(r);
    assertLoopback(r.url);
    const auth = r.headers.Authorization ?? '';
    if (auth === 'Bearer owner') return { status: 200, body: '{}' };
    let uid: string | null = null;
    if (auth.startsWith('Bearer ')) uid = (JSON.parse(Buffer.from(auth.slice(7).split('.')[1]!, 'base64url').toString()) as { user_id: string }).user_id;
    const u = new URL(r.url);
    const docPath = decodeURIComponent(u.pathname.split('/documents/')[1] ?? '');
    const segs = docPath.split('/').filter(Boolean);
    let op: Op;
    if (r.method === 'GET') op = segs.length % 2 === 0 ? 'list' : 'get';
    else if (r.method === 'DELETE') op = 'delete';
    else op = u.searchParams.get('currentDocument.exists') === 'false' ? 'create' : 'update';
    return policy(uid, op, docPath) ? { status: 200, body: '{"ok":true}' } : { status: 403, body: '{"error":{"code":403,"status":"PERMISSION_DENIED"}}' };
  };
  return { transport, seen };
}

const mockEnv = (t: Transport) => ({ transport: t, projectId: 'demo-x', bucket: 'demo-x.appspot.com', firestoreBase: 'http://127.0.0.1:1', storageBase: 'http://127.0.0.1:2' });

async function run(rules: string, policy: Policy) {
  const files = [{ relPath: 'firestore.rules', source: rules }];
  const plan = buildPlan(files);
  const st = scanFirebaseFiles(files).findings;
  const { transport, seen } = fakeEmulator(policy);
  const results = await runPlan(mockEnv(transport), plan.targets);
  return { plan, st, results, seen, rec: reconcile(st, results) };
}

describe('firebase emulator plan', () => {
  it('builds one target per match path with concrete ids, owner var bound to the owner', () => {
    const p = planRulesFile({ relPath: 'firestore.rules', source: FS(`match /users/{userId} { allow read, write: if request.auth.uid == userId; }\n match /posts/{postId} { allow read: if true; allow update: if resource.data.ownerId == request.auth.uid; }`) });
    expect(p.targets.map((t) => t.docPath)).toEqual(['users/alice', 'posts/dr-postId']);
    expect(p.targets[1]!.ownerFields).toEqual(['ownerId']);
    expect(p.targets[0]!.lines).toHaveLength(1);
  });
  it('handles recursive wildcards (even segment count for Firestore) and storage object names', () => {
    const f = planRulesFile({ relPath: 'firestore.rules', source: FS('match /{document=**} { allow read: if true; }') });
    expect(f.targets[0]!.docPath).toBe('dr-col/dr-doc');
    const s = planRulesFile({ relPath: 'storage.rules', source: "rules_version = '2';\nservice firebase.storage {\n match /b/{bucket}/o {\n match /users/{userId}/{allPaths=**} { allow read: if request.auth.uid == userId; }\n }\n}\n" });
    expect(s.targets[0]).toMatchObject({ service: 'storage', docPath: 'users/alice/dr-obj.txt', collectionPath: 'users/alice/' });
  });
  it('skips collection-level matches and reports why', () => {
    const p = planRulesFile({ relPath: 'firestore.rules', source: FS('match /config { allow read: if true; }') });
    expect(p.targets).toHaveLength(0);
    expect(p.skipped[0]).toMatch(/collection-level/);
  });
  it('picks one rules file per service, preferring firebase.json', () => {
    const r = (s: string) => ({ relPath: s, source: FS('match /a/{x} { allow read: if true; }') });
    const { chosen, notes } = pickRulesFiles([
      { relPath: 'firebase.json', source: '{"firestore":{"rules":"cfg/firestore.rules"}}' },
      r('firestore.rules'), r('cfg/firestore.rules'),
    ]);
    expect(chosen.map((c) => c.relPath)).toEqual(['cfg/firestore.rules']);
    expect(notes[0]).toMatch(/firestore\.rules: not tested/);
  });
});

describe('firebase emulator matrix + reconciliation (mocked emulator)', () => {
  it('open rules: confirmed with proof, static finding keeps its rule id', async () => {
    const r = await run(FS('match /messages/{id} { allow read, write: if true; }'), () => true);
    expect(r.results[0]!.probes).toHaveLength(15);
    const f = r.rec.staticFindings.find((x) => x.rule === 'firebase-rules-open')!;
    expect(f.proof?.status).toBe(200);
    expect(f.proof?.request).toContain('curl -X');
    expect(f.proof?.request).not.toContain(emulatorToken('bob', 'demo-x'));
    expect(f.description).toMatch(/Confirmed by the Firebase emulator/);
    expect(r.rec.emulatorFindings).toHaveLength(0);
    expect(r.rec.confirmed).toBe(1);
  });
  it('static miss: emulator allows what static passed -> critical emulator finding', async () => {
    const rules = FS('match /users/{userId} { allow read, write: if resource == null || request.auth != null; }');
    const r = await run(rules, (uid, op) => (uid === null ? op === 'create' : true));
    expect(r.st).toHaveLength(0);
    const f = r.rec.emulatorFindings;
    expect(f.map((x) => x.rule)).toContain('firebase-emulator-open-access');
    const open = f.find((x) => x.rule === 'firebase-emulator-open-access')!;
    expect(open).toMatchObject({ severity: 'critical', source: 'dynamic', file: 'firestore.rules' });
    expect(open.description).toMatch(/Static analysis did not flag/);
    expect(open.proof?.control).toMatch(/HTTP 200/);
    expect(r.rec.staticMisses).toBeGreaterThan(0);
  });
  it('owner check missing: any signed-in user writes -> static critical confirmed, read warning confirmed too', async () => {
    const r = await run(FS('match /users/{userId} { allow read, write: if request.auth != null; }'), (uid) => uid !== null);
    const statics = r.rec.staticFindings.filter((x) => x.rule === 'firebase-rules-auth-only');
    expect(statics.length).toBeGreaterThan(0);
    expect(statics.every((x) => x.proof)).toBe(true);
    expect(r.rec.emulatorFindings).toHaveLength(0);
  });
  it('owner-only rules: nothing exposed, no findings', async () => {
    const r = await run(FS('match /users/{userId} { allow read, write: if request.auth.uid == userId; }'), (uid) => uid === 'alice');
    expect(r.rec.emulatorFindings).toHaveLength(0);
    expect(r.rec.staticFindings).toHaveLength(0);
  });
  it('static flagged but emulator denies everything -> downgraded to a not-reproduced note', async () => {
    const r = await run(FS('match /messages/{id} { allow read, write: if request.time < timestamp.date(2020, 1, 1); }'), () => false);
    const f = r.rec.staticFindings.find((x) => x.rule === 'firebase-rules-test-mode')!;
    expect(f).toMatchObject({ note: true, severity: 'info', suggestedSeverity: 'warning' });
    expect(f.title).toMatch(/^Not reproduced/);
    expect(r.rec.notReproduced).toBe(1);
  });
  it('does not downgrade when probes were inconclusive (e.g. server errors)', async () => {
    const files = [{ relPath: 'firestore.rules', source: FS('match /messages/{id} { allow read, write: if true; }') }];
    const plan = buildPlan(files);
    const t: Transport = async (r) => (r.headers.Authorization === 'Bearer owner' ? { status: 200, body: '' } : { status: 500, body: 'boom' });
    const results = await runPlan(mockEnv(t), plan.targets);
    const rec = reconcile(scanFirebaseFiles(files).findings, results);
    expect(rec.notReproduced).toBe(0);
    expect(rec.staticFindings.find((x) => x.rule === 'firebase-rules-open')!.note).toBeUndefined();
  });
  it('shared signed-in reads on a non-user path are a note, not a finding', async () => {
    const rules = FS('match /posts/{id} { allow read: if request.auth != null && true == true; allow write: if request.auth.uid == resource.data.ownerId; }');
    const r = await run(rules, (uid, op) => uid !== null && (op === 'get' || op === 'list' || uid === 'alice'));
    const f = r.rec.emulatorFindings.find((x) => x.rule === 'firebase-emulator-owner-check-missing')!;
    expect(f.note).toBe(true);
    expect(f.severity).toBe('info');
  });
  it('a seed failure marks the target errored instead of guessing', async () => {
    const files = [{ relPath: 'firestore.rules', source: FS('match /m/{id} { allow read: if true; }') }];
    const results = await runPlan(mockEnv(async () => ({ status: 500, body: 'nope' })), buildPlan(files).targets);
    expect(results[0]!.error).toMatch(/seed failed/);
  });
});

describe('safety', () => {
  it('only loopback http is ever contacted', () => {
    expect(() => assertLoopback('http://127.0.0.1:8080/x')).not.toThrow();
    expect(() => assertLoopback('http://localhost:8080/x')).not.toThrow();
    expect(() => assertLoopback('https://firestore.googleapis.com/v1/projects/p')).toThrow(/non-loopback/);
    expect(() => assertLoopback('http://10.0.0.5:8080/')).toThrow(/non-loopback/);
  });
  it('parses java versions', () => {
    expect(parseJavaMajor('openjdk version "21.0.13.1" 2026-11-17')).toBe(21);
    expect(parseJavaMajor('java version "1.8.0_292"')).toBe(8);
    expect(parseJavaMajor('nothing')).toBeUndefined();
  });
});

describe('opt-in step + coverage', () => {
  const tooling = { ok: false, reason: 'the firebase CLI (firebase-tools) was not found on PATH. Install firebase-tools yourself (npm install -g firebase-tools; MIT licensed) and a JDK.' };
  it('missing tools -> untested with install hint', async () => {
    const out = await runEmulatorChecks(path.join(CORPUS, 'firestore-open-true-tp'), [], { tooling });
    expect(out.state).toBe('untested');
    expect(out.reason).toMatch(/Install firebase-tools yourself/);
  });
  it('project without firestore/storage rules is not-applicable', async () => {
    const out = await runEmulatorChecks(path.join(CORPUS, 'rtdb-open-tp'), [], { tooling });
    expect(out.state).toBe('not-applicable');
  });
  it('firebaseStep does nothing emulator-related unless opted in', async () => {
    const r = await firebaseStep(path.join(CORPUS, 'firestore-open-true-tp'), { json: true });
    expect(r.emulatorCoverage).toBeUndefined();
    expect(r.liveFindings).toEqual([]);
  });
  it('firebaseStep with the flag and no CLI reports untested (requested)', async () => {
    const saved = { PATH: process.env.PATH, BIN: process.env.DEPLOYREADY_FIREBASE_BIN };
    process.env.PATH = '/nonexistent-deployready';
    delete process.env.DEPLOYREADY_FIREBASE_BIN;
    try {
      const r = await firebaseStep(path.join(CORPUS, 'firestore-open-true-tp'), { json: true, firebaseEmulator: true });
      expect(r.emulatorCoverage).toMatchObject({ state: 'untested', requested: true });
      expect(r.emulatorCoverage!.reason).toMatch(/never installs|Install firebase-tools yourself/);
      expect(r.coverage?.state).toBe('passed'); // static is unaffected
    } finally {
      process.env.PATH = saved.PATH;
      if (saved.BIN !== undefined) process.env.DEPLOYREADY_FIREBASE_BIN = saved.BIN;
    }
  });
  it('adapter metadata follows the engine adapter contract', () => {
    expect(firebaseEmulatorAdapter).toMatchObject({ id: 'firebase-emulator', optIn: true, networked: false });
    expect(firebaseEmulatorAdapter.applicable(path.join(CORPUS, 'firestore-open-true-tp'), { offline: false, timeoutMs: 1 })).toBe(true);
    expect(firebaseEmulatorAdapter.applicable(path.join(CORPUS, 'rtdb-open-tp'), { offline: false, timeoutMs: 1 })).toBe(false);
  });
});

// Real emulator tests: need firebase-tools + Java. Run with FIREBASE_EMULATOR_TESTS=1
// (and DEPLOYREADY_FIREBASE_BIN=/path/to/firebase if it is not on PATH).
const real = process.env.FIREBASE_EMULATOR_TESTS === '1' ? describe : describe.skip;
real('real Firebase Emulator Suite', () => {
  jest.setTimeout(300_000);
  const scan = async (id: string) => {
    const dir = path.join(CORPUS, id);
    const st = await scanFirebaseStatic(dir);
    return runEmulatorChecks(dir, st.findings);
  };
  it('open rules are confirmed', async () => {
    const o = await scan('firestore-open-true-tp');
    expect(o.state).toBe('passed');
    expect(o.reconciled!.staticFindings.find((f) => f.rule === 'firebase-rules-open')!.proof?.status).toBe(200);
  });
  it('owner rules expose nothing to anonymous or other users on /users', async () => {
    const o = await scan('storage-owner-tn');
    expect(o.state).toBe('passed');
    expect(o.reconciled!.emulatorFindings).toHaveLength(0);
  });
  it('catches a rule the static reader misses, and does not reproduce an expired test-mode rule', async () => {
    const miss = await scan('firestore-null-resource-emu');
    expect(miss.reconciled!.emulatorFindings.map((f) => f.rule)).toContain('firebase-emulator-open-access');
    const stale = await scan('firestore-expired-test-mode-emu');
    expect(stale.reconciled!.staticFindings.find((f) => f.rule === 'firebase-rules-test-mode')!.note).toBe(true);
  });
  it('storage: owner-only writes with public reads', async () => {
    const o = await scan('storage-public-read-emu');
    const f = o.reconciled!.staticFindings.find((x) => x.rule === 'firebase-rules-open-read')!;
    expect(f.proof?.status).toBe(200);
    expect(o.reconciled!.emulatorFindings.filter((x) => x.severity === 'critical')).toHaveLength(0);
  });
});
