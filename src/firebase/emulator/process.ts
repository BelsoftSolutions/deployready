/**
 * Starts the official Firebase emulators (Firestore + Storage) from the
 * user-installed firebase-tools, in a throwaway directory, bound to 127.0.0.1,
 * under a `demo-` project id (which can never address a real project).
 * DeployReady never installs firebase-tools or Java.
 */
import { spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { findOnPath, minimalEnv, runBinary } from '../../adapters/exec';
import { redact } from '../../utils/redact';
import { assertLoopback, loopbackTransport } from './probe';

export interface Tooling {
  ok: boolean;
  firebaseBin?: string;
  firebaseVersion?: string;
  javaBin?: string;
  javaMajor?: number;
  /** Why it is not usable, with an install hint. */
  reason?: string;
}

export const INSTALL_HINT =
  'Install firebase-tools yourself (npm install -g firebase-tools; MIT licensed) and a JDK 11 or newer (21 recommended). DeployReady never installs them.';

export function parseJavaMajor(text: string): number | undefined {
  const m = /version "(\d+)(?:\.(\d+))?/.exec(text);
  if (!m) return undefined;
  const major = Number(m[1]);
  return major === 1 && m[2] ? Number(m[2]) : major;
}

export async function detectTooling(): Promise<Tooling> {
  const firebaseBin = process.env.DEPLOYREADY_FIREBASE_BIN || findOnPath('firebase');
  const javaBin = findOnPath('java');
  const problems: string[] = [];
  let firebaseVersion: string | undefined;
  let javaMajor: number | undefined;
  if (!firebaseBin) problems.push('the firebase CLI (firebase-tools) was not found on PATH');
  else {
    const r = await runBinary(firebaseBin, ['--version'], { cwd: process.cwd(), timeoutMs: 30_000 });
    firebaseVersion = r.code === 0 ? r.stdout.match(/\d+\.\d+\.\d+/)?.[0] : undefined;
    if (r.code !== 0) problems.push('`firebase --version` failed');
  }
  if (!javaBin) problems.push('Java was not found on PATH');
  else {
    const r = await runBinary(javaBin, ['-version'], { cwd: process.cwd(), timeoutMs: 30_000 });
    javaMajor = parseJavaMajor(`${r.stderr}\n${r.stdout}`);
    if (javaMajor !== undefined && javaMajor < 11) problems.push(`Java ${javaMajor} is too old (the emulators need 11+)`);
  }
  if (problems.length) return { ok: false, firebaseBin, firebaseVersion, javaBin, javaMajor, reason: `${problems.join('; ')}. ${INSTALL_HINT}` };
  return { ok: true, firebaseBin, firebaseVersion, javaBin, javaMajor };
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(p));
    });
  });
}

export interface RunningEmulators {
  projectId: string;
  bucket: string;
  firestoreBase?: string;
  storageBase?: string;
  stop(): Promise<void>;
}

export interface StartOptions {
  firebaseBin: string;
  /** rules file contents to load, by service */
  firestoreRules?: string;
  storageRules?: string;
  startupTimeoutMs: number;
}

async function waitFor(url: string, until: number, child: ChildProcess): Promise<void> {
  const t = loopbackTransport(3000);
  while (Date.now() < until) {
    if (child.exitCode !== null) throw new Error(`emulator process exited (code ${child.exitCode})`);
    try {
      const r = await t({ method: 'GET', url, headers: {} });
      if (r.status > 0) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error('timed out waiting for the emulator to start');
}

export async function startEmulators(o: StartOptions): Promise<RunningEmulators> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deployready-fbemu-'));
  const projectId = `demo-deployready-${Date.now().toString(36)}`;
  const emulators: Record<string, unknown> = { ui: { enabled: false }, singleProjectMode: true };
  const cfg: Record<string, unknown> = { emulators };
  const only: string[] = [];
  let fsPort: number | undefined;
  let stPort: number | undefined;
  if (o.firestoreRules !== undefined) {
    fs.writeFileSync(path.join(dir, 'firestore.rules'), o.firestoreRules);
    fsPort = await freePort();
    cfg.firestore = { rules: 'firestore.rules' };
    emulators.firestore = { host: '127.0.0.1', port: fsPort, websocketPort: await freePort() };
    only.push('firestore');
  }
  if (o.storageRules !== undefined) {
    fs.writeFileSync(path.join(dir, 'storage.rules'), o.storageRules);
    stPort = await freePort();
    cfg.storage = { rules: 'storage.rules' };
    emulators.storage = { host: '127.0.0.1', port: stPort };
    only.push('storage');
  }
  emulators.hub = { host: '127.0.0.1', port: await freePort() };
  emulators.logging = { host: '127.0.0.1', port: await freePort() };
  fs.writeFileSync(path.join(dir, 'firebase.json'), JSON.stringify(cfg));

  // Minimal env: no cloud credentials. HOME is kept so firebase-tools finds its cached emulator jars.
  const env = minimalEnv({ FIREBASE_EMULATORS_PATH: process.env.FIREBASE_EMULATORS_PATH ?? '' });
  if (!env.FIREBASE_EMULATORS_PATH) delete env.FIREBASE_EMULATORS_PATH;
  const child = spawn(o.firebaseBin, ['emulators:start', '--only', only.join(','), '--project', projectId, '--config', 'firebase.json', '--non-interactive'], {
    cwd: dir, env, shell: false, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
  });
  let log = '';
  const keep = (b: Buffer): void => { log = (log + b.toString('utf8')).slice(-4000); };
  child.stdout?.on('data', keep);
  child.stderr?.on('data', keep);

  let stopped = false;
  const stop = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    const kill = (sig: NodeJS.Signals): void => {
      try {
        if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, sig);
        else child.kill(sig);
      } catch { /* already gone */ }
    };
    kill('SIGTERM');
    await new Promise<void>((resolve) => {
      const t = setTimeout(() => { kill('SIGKILL'); resolve(); }, 5000);
      child.once('exit', () => { clearTimeout(t); resolve(); });
      if (child.exitCode !== null) { clearTimeout(t); resolve(); }
    });
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  };

  const until = Date.now() + o.startupTimeoutMs;
  const base = (p: number): string => `http://127.0.0.1:${p}`;
  try {
    if (fsPort) { assertLoopback(base(fsPort)); await waitFor(base(fsPort) + '/', until, child); }
    if (stPort) { assertLoopback(base(stPort)); await waitFor(base(stPort) + '/', until, child); }
  } catch (e) {
    await stop();
    throw new Error(`${(e as Error).message}. Emulator output: ${redact(log.replace(/JAVA_TOOL_OPTIONS[^\n]*/g, '')).slice(-600)}`);
  }
  return { projectId, bucket: `${projectId}.appspot.com`, firestoreBase: fsPort ? base(fsPort) : undefined, storageBase: stPort ? base(stPort) : undefined, stop };
}
