/**
 * Firebase Emulator Suite adapter (firebase-tools, MIT, https://github.com/firebase/firebase-tools).
 * Opt-in via `--firebase-emulator`. Uses only a user-installed `firebase` CLI and Java; it never
 * installs either. Everything runs on 127.0.0.1 under a throwaway `demo-` project, so no real
 * Firebase project is ever contacted. The module driving it lives in src/firebase/emulator.
 */
import * as fs from 'fs';
import * as path from 'path';
import type { EngineAdapter, EngineDetection, EngineResult, EngineRunOptions } from './types';
import { emptyCoverage, result } from './common';
import { detectTooling, runEmulatorChecks } from '../firebase/emulator';
import { scanFirebaseStatic } from '../firebase/static';

const ID = 'firebase-emulator';

export const firebaseEmulatorAdapter: EngineAdapter = {
  id: ID,
  label: 'Firebase Emulator Suite (security rules proof)',
  capabilities: ['sast'],
  networked: false, // loopback only
  optIn: true,
  async detect(): Promise<EngineDetection> {
    const t = await detectTooling();
    return { installed: t.ok, version: t.firebaseVersion, path: t.firebaseBin };
  },
  applicable(projectRoot: string, _opts: EngineRunOptions): boolean {
    return ['firestore.rules', 'storage.rules'].some((f) => fs.existsSync(path.join(projectRoot, f)));
  },
  /** Findings produced by the emulator alone (not reconciled with the static scan; firebaseStep does that). */
  async run(projectRoot: string, _opts: EngineRunOptions): Promise<EngineResult> {
    const started = Date.now();
    const cov = emptyCoverage();
    const st = await scanFirebaseStatic(projectRoot);
    const out = await runEmulatorChecks(projectRoot, st.findings);
    for (const r of out.results) if (!r.error) cov.checked.push(`${r.target.file} ${r.target.display}`);
    cov.skipped.push(...out.skipped);
    if (out.state === 'untested' || out.state === 'failed') cov.errors.push(out.reason);
    return result(out.reconciled?.emulatorFindings ?? [], cov, started);
  },
};
