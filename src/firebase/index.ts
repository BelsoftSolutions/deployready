/**
 * Firebase module entry point. Static only in this release: no network and no
 * live probing. See docs/FIREBASE.md.
 */
import { logger } from '../utils/logger';
import { redact } from '../utils/redact';
import { scanFirebaseStatic } from './static';
import type { CoverageState, Finding } from '../types';

export { scanFirebaseStatic, scanFirebaseFiles } from './static';
export { scanFirebaseRules, scanRtdbRules } from './rules';

/** Orchestrator hook. Never throws. */
export async function firebaseStep(
  projectPath: string,
  opts: { json?: boolean },
): Promise<{ staticFindings: Finding[]; coverage?: { state: CoverageState; reason: string } }> {
  try {
    const res = await scanFirebaseStatic(projectPath);
    for (const n of res.notes) (opts.json ? logger.stderr : logger.info.bind(logger))(redact(n));
    const coverage = res.detected
      ? { state: 'passed' as const, reason: 'Firebase rules and config checked statically.' }
      : { state: 'not-applicable' as const, reason: 'No Firebase project detected.' };
    return { staticFindings: res.findings, coverage };
  } catch (err) {
    const msg = redact((err as Error).message);
    logger.warn(`Firebase checks failed: ${msg}`);
    // A crashed step is never a pass.
    return { staticFindings: [], coverage: { state: 'failed', reason: `Firebase checks errored: ${msg}` } };
  }
}
