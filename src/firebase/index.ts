/**
 * Firebase module entry point. Static only in this release: no network and no
 * live probing. See docs/FIREBASE.md.
 */
import { logger } from '../utils/logger';
import { redact } from '../utils/redact';
import { scanFirebaseStatic } from './static';
import { runEmulatorChecks, INSTALL_HINT } from './emulator';
import type { CoverageState, Finding } from '../types';

export { scanFirebaseStatic, scanFirebaseFiles } from './static';
export { scanFirebaseRules, scanRtdbRules } from './rules';

export interface FirebaseStepResult {
  staticFindings: Finding[];
  /** Emulator-only findings (proof-backed). */
  liveFindings: Finding[];
  coverage?: { state: CoverageState; reason: string };
  /** Coverage of the opt-in emulator proof (`--firebase-emulator`). */
  emulatorCoverage?: { state: CoverageState; reason: string; requested: boolean };
}

/** Orchestrator hook. Never throws. `firebaseEmulator` is the opt-in `--firebase-emulator` flag. */
export async function firebaseStep(
  projectPath: string,
  opts: { json?: boolean; firebaseEmulator?: boolean },
): Promise<FirebaseStepResult> {
  try {
    const res = await scanFirebaseStatic(projectPath);
    for (const n of res.notes) (opts.json ? logger.stderr : logger.info.bind(logger))(redact(n));
    const coverage = res.detected
      ? { state: 'passed' as const, reason: 'Firebase rules and config checked statically.' }
      : { state: 'not-applicable' as const, reason: 'No Firebase project detected.' };
    let staticFindings = res.findings;
    let liveFindings: Finding[] = [];
    let emulatorCoverage: FirebaseStepResult['emulatorCoverage'];
    if (opts.firebaseEmulator) {
      try {
        const out = await runEmulatorChecks(projectPath, res.findings);
        if (out.reconciled) { staticFindings = out.reconciled.staticFindings; liveFindings = out.reconciled.emulatorFindings; }
        emulatorCoverage = { state: out.state, reason: out.reason, requested: true };
      } catch (err) {
        emulatorCoverage = { state: 'failed', reason: `Firebase emulator checks errored: ${redact((err as Error).message)}`, requested: true };
      }
      if (emulatorCoverage.state === 'untested') logger.warn(redact(emulatorCoverage.reason));
    }
    return { staticFindings, liveFindings, coverage, emulatorCoverage };
  } catch (err) {
    const msg = redact((err as Error).message);
    logger.warn(`Firebase checks failed: ${msg}`);
    // A crashed step is never a pass.
    return { staticFindings: [], liveFindings: [], coverage: { state: 'failed', reason: `Firebase checks errored: ${msg}` }, emulatorCoverage: opts.firebaseEmulator ? { state: 'failed', reason: 'Firebase checks errored before the emulator ran.', requested: true } : undefined };
  }
}

export { INSTALL_HINT };
