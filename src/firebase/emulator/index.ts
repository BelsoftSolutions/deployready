/** Emulator-backed rules testing: pick rules files, start emulators, run the matrix, reconcile. */
import * as path from 'path';
import { readFirebaseFiles, isRulesFile, type SourceFile } from '../static';
import { parseRules } from '../rulesParser';
import { parseJsonLoose } from '../rtdbParser';
import type { Finding } from '../../types';
import { buildPlan, type RulesInput } from './plan';
import { runPlan, loopbackTransport, type TargetResult, type Transport } from './probe';
import { reconcile, type Reconciled } from './reconcile';
import { detectTooling, startEmulators, type Tooling } from './process';

export * from './plan';
export * from './probe';
export * from './reconcile';
export { detectTooling, INSTALL_HINT, parseJavaMajor } from './process';

export type EmuCoverageState = 'passed' | 'untested' | 'inconclusive' | 'failed' | 'not-applicable';

export interface EmulatorRunOptions {
  /** Emulator startup timeout (the first run may download the emulator jars). Default 240 s. */
  startupTimeoutMs?: number;
  /** Tests: use a prepared transport + base URLs instead of starting emulators. */
  mock?: { transport: Transport; projectId: string; bucket: string; firestoreBase?: string; storageBase?: string };
  /** Tests: skip tool detection. */
  tooling?: Tooling;
}

export interface EmulatorOutcome {
  state: EmuCoverageState;
  reason: string;
  results: TargetResult[];
  skipped: string[];
  /** Static findings reconciled with the emulator results. */
  reconciled?: Reconciled;
}

/** Choose one rules file per service: the one firebase.json names, else the root one, else the shallowest. */
export function pickRulesFiles(files: SourceFile[]): { chosen: RulesInput[]; notes: string[] } {
  const rules = files.filter((f) => isRulesFile(f.relPath));
  const named = new Set<string>();
  const fj = files.find((f) => f.relPath === 'firebase.json');
  const root = fj ? parseJsonLoose(fj.source) : undefined;
  if (root?.t === 'obj') {
    for (const k of ['firestore', 'storage']) {
      const v = root.entries.find((e) => e.key === k)?.val;
      if (v?.t === 'obj') {
        const r = v.entries.find((e) => e.key === 'rules')?.val;
        if (r && r.t === 'str') named.add(path.posix.normalize(r.v));
      }
    }
  }
  const by: Record<string, SourceFile[]> = { firestore: [], storage: [] };
  for (const f of rules) {
    const svc = parseRules(f.source).service;
    const kind = svc === 'unknown' ? (/storage/i.test(f.relPath) ? 'storage' : 'firestore') : svc;
    by[kind]!.push(f);
  }
  const chosen: RulesInput[] = [];
  const notes: string[] = [];
  for (const [svc, list] of Object.entries(by)) {
    if (!list.length) continue;
    list.sort((a, b) => Number(named.has(b.relPath)) - Number(named.has(a.relPath)) || a.relPath.split('/').length - b.relPath.split('/').length || a.relPath.localeCompare(b.relPath));
    chosen.push(list[0]!);
    for (const extra of list.slice(1)) notes.push(`${extra.relPath}: not tested (another ${svc} rules file, ${list[0]!.relPath}, was chosen)`);
  }
  return { chosen, notes };
}

export async function runEmulatorChecks(projectRoot: string, staticFindings: Finding[], opts: EmulatorRunOptions = {}): Promise<EmulatorOutcome> {
  const { files } = await readFirebaseFiles(projectRoot);
  const { chosen, notes } = pickRulesFiles(files);
  if (chosen.length === 0) return { state: 'not-applicable', reason: 'No firestore.rules or storage.rules to test with the emulator.', results: [], skipped: [] };
  const plan = buildPlan(chosen);
  const skipped = [...notes, ...plan.skipped];
  if (plan.targets.length === 0) return { state: 'inconclusive', reason: `No testable rules paths found (${skipped.join('; ') || 'no allow statements'}).`, results: [], skipped };

  let results: TargetResult[];
  if (opts.mock) {
    results = await runPlan({ ...opts.mock }, plan.targets);
  } else {
    const tooling = opts.tooling ?? (await detectTooling());
    if (!tooling.ok || !tooling.firebaseBin) {
      return { state: 'untested', reason: `Firebase emulator not run: ${tooling.reason ?? 'firebase CLI missing'}`, results: [], skipped };
    }
    const svc = (s: string): string | undefined => chosen.find((c) => plan.targets.some((t) => t.file === c.relPath && t.service === s))?.source;
    let emu;
    try {
      emu = await startEmulators({ firebaseBin: tooling.firebaseBin, firestoreRules: svc('firestore'), storageRules: svc('storage'), startupTimeoutMs: opts.startupTimeoutMs ?? 240_000 });
    } catch (e) {
      return { state: 'failed', reason: `Firebase emulator could not start: ${(e as Error).message}`, results: [], skipped };
    }
    try {
      results = await runPlan({ transport: loopbackTransport(), projectId: emu.projectId, bucket: emu.bucket, firestoreBase: emu.firestoreBase, storageBase: emu.storageBase }, plan.targets);
    } finally {
      await emu.stop();
    }
  }
  const errors = results.filter((r) => r.error);
  const rec = reconcile(staticFindings, results);
  const tested = results.length - errors.length;
  const exposed = results.filter((r) => !r.error && r.probes.some((p) => p.allowed && p.actor !== 'userA')).length;
  const inconclusive = errors.length > 0 || results.some((r) => r.probes.some((p) => !p.definitive)) || skipped.length > 0;
  const reason = `Firebase emulator tested ${tested} rules path(s) as anonymous, owner and non-owner (get/list/create/update/delete); ${exposed} exposed${rec.notReproduced ? `, ${rec.notReproduced} static finding(s) not reproduced` : ''}${errors.length ? `; ${errors.length} path(s) errored (${errors[0]!.error})` : ''}${skipped.length ? `; ${skipped.length} path(s) not tested` : ''}.`;
  return { state: tested === 0 ? 'failed' : inconclusive ? 'inconclusive' : 'passed', reason, results, skipped, reconciled: rec };
}

