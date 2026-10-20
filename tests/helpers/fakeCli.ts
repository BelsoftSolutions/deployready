/**
 * A fake `claude` / `codex` CLI for tests. It is a tiny Node script behind a platform shim
 * (.cmd on Windows, shell script elsewhere) that RECORDS everything it was given (argv, cwd,
 * directory listing, full environment, stdin) and replies from behavior.json. No network, no
 * model, no credentials: "verified with fakes only".
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export interface FakeReply {
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  /** Delay before replying. */
  sleepMs?: number;
  /** Never exit (for the timeout test). */
  hang?: boolean;
  /** Start a long-lived grandchild and record its pid in child.pid. */
  spawnChild?: boolean;
  /** Emit this many bytes of 'x' instead of stdout. */
  bigBytes?: number;
}

export interface FakeBehavior {
  version?: FakeReply;
  status?: FakeReply;
  run?: FakeReply;
  /** After a successful fake login, replace the status reply with this. */
  login?: FakeReply & { thenStatus?: FakeReply };
}

export interface FakeRecord {
  kind: 'version' | 'status' | 'login' | 'run';
  argv: string[];
  cwd: string;
  cwdEntries: string[];
  env: Record<string, string>;
  stdin: string;
}

const SCRIPT = `
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const dir = __dirname;
const argv = process.argv.slice(2);
const behPath = path.join(dir, 'behavior.json');
const beh = JSON.parse(fs.readFileSync(behPath, 'utf8'));
let kind = 'run';
if (argv[0] === '--version') kind = 'version';
else if ((argv[0] === 'auth' && argv[1] === 'status') || (argv[0] === 'login' && argv[1] === 'status')) kind = 'status';
else if (argv[0] === 'login' || (argv[0] === 'auth' && argv[1] === 'login')) kind = 'login';
const reply = beh[kind] || {};

function finish(stdin) {
  let entries = [];
  try { entries = fs.readdirSync(process.cwd()); } catch (e) {}
  fs.appendFileSync(path.join(dir, 'record.jsonl'), JSON.stringify({ kind, argv, cwd: process.cwd(), cwdEntries: entries, env: process.env, stdin }) + '\\n');
  if (kind === 'login' && reply.thenStatus) { beh.status = reply.thenStatus; fs.writeFileSync(behPath, JSON.stringify(beh)); }
  const go = () => {
    if (reply.spawnChild) {
      const c = spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], { stdio: 'ignore', detached: false });
      fs.writeFileSync(path.join(dir, 'child.pid'), String(c.pid));
    }
    if (reply.hang) { setInterval(() => {}, 1000); return; }
    if (reply.bigBytes) process.stdout.write('x'.repeat(reply.bigBytes));
    else if (reply.stdout) process.stdout.write(reply.stdout);
    if (reply.stderr) process.stderr.write(reply.stderr);
    process.exitCode = reply.exitCode || 0;
  };
  if (reply.sleepMs) setTimeout(go, reply.sleepMs); else go();
}

if (kind === 'run') {
  let data = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => { data += c; });
  process.stdin.on('end', () => finish(data));
} else {
  finish('');
}
`;

export interface FakeCli {
  /** Absolute path of the claude/codex shim (this is what `cliCommand` points at). */
  command: string;
  /** Directory that holds the shim (put it on PATH to test discovery). */
  dir: string;
  setBehavior(b: FakeBehavior): void;
  records(): FakeRecord[];
  runs(): FakeRecord[];
  childPid(): number | undefined;
  cleanup(): void;
}

export function realTmp(): string {
  return fs.realpathSync.native(os.tmpdir());
}

export function makeFakeCli(name: 'claude' | 'codex', behavior: FakeBehavior = {}, opts: { dirName?: string } = {}): FakeCli {
  const dir = fs.mkdtempSync(path.join(realTmp(), `${opts.dirName ?? 'fake cli '}`));
  fs.writeFileSync(path.join(dir, 'fake.js'), SCRIPT);
  const shimBody =
    process.platform === 'win32'
      ? `@echo off\r\n"${process.execPath}" "${path.join(dir, 'fake.js')}" %*\r\n`
      : `#!/bin/sh\nexec "${process.execPath}" "${path.join(dir, 'fake.js')}" "$@"\n`;
  const command = path.join(dir, process.platform === 'win32' ? `${name}.cmd` : name);
  fs.writeFileSync(command, shimBody, { mode: 0o755 });
  const write = (b: FakeBehavior): void => fs.writeFileSync(path.join(dir, 'behavior.json'), JSON.stringify(b));
  write(behavior);

  const records = (): FakeRecord[] => {
    const file = path.join(dir, 'record.jsonl');
    if (!fs.existsSync(file)) return [];
    return fs
      .readFileSync(file, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as FakeRecord);
  };

  return {
    command,
    dir,
    setBehavior: write,
    records,
    runs: () => records().filter((r) => r.kind === 'run'),
    childPid: () => {
      const f = path.join(dir, 'child.pid');
      return fs.existsSync(f) ? Number(fs.readFileSync(f, 'utf8')) : undefined;
    },
    cleanup: () => {
      const pid = fs.existsSync(path.join(dir, 'child.pid')) ? Number(fs.readFileSync(path.join(dir, 'child.pid'), 'utf8')) : undefined;
      if (pid) {
        try {
          process.kill(pid, 'SIGKILL');
        } catch {
          /* already gone */
        }
      }
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
  };
}

export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Environment for a CLI test: only what the fake needs, plus any sentinel names the test adds. */
export function testEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const base: NodeJS.ProcessEnv = {};
  for (const k of ['SystemRoot', 'windir', 'PATHEXT', 'ComSpec', 'PATH']) if (process.env[k]) base[k] = process.env[k];
  return { ...base, ...extra };
}


/** The canned Claude CLI JSON result. */
export function claudeOk(result: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ type: 'result', subtype: 'success', is_error: false, result, num_turns: 1, permission_denials: [], ...extra });
}

/** The canned Codex `exec --json` event stream with a final agent message. */
export function codexOk(text: string): string {
  return [
    JSON.stringify({ type: 'thread.started', thread_id: 't' }),
    JSON.stringify({ type: 'turn.started' }),
    JSON.stringify({ type: 'item.completed', item: { id: 'i0', type: 'agent_message', text } }),
    JSON.stringify({ type: 'turn.completed', usage: {} }),
  ].join('\n') + '\n';
}
