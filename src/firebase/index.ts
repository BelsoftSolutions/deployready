/**
 * Firebase module entry point. Static only in this release: no network and no
 * live probing. See docs/FIREBASE.md.
 */
import { logger } from '../utils/logger';
import { redact } from '../utils/redact';
import { scanFirebaseStatic } from './static';
import type { Finding } from '../types';

export { scanFirebaseStatic, scanFirebaseFiles } from './static';
export { scanFirebaseRules, scanRtdbRules } from './rules';

/** Orchestrator hook. Never throws. */
export async function firebaseStep(
  projectPath: string,
  opts: { json?: boolean },
): Promise<{ staticFindings: Finding[] }> {
  try {
    const res = await scanFirebaseStatic(projectPath);
    for (const n of res.notes) (opts.json ? logger.stderr : logger.info.bind(logger))(redact(n));
    return { staticFindings: res.findings };
  } catch (err) {
    logger.warn(`Firebase checks failed: ${redact((err as Error).message)}`);
    return { staticFindings: [] };
  }
}
