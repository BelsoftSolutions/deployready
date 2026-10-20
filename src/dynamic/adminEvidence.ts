/**
 * Classify an already-discovered route as admin-like from evidence in its own
 * path and guard names. Never produces a request; whole words only.
 */
import { splitWords } from '../parser/adapters/authMiddleware';

const ADMIN_VOCABULARY = new Set([
  'admin',
  'admins',
  'administrator',
  'administrators',
  'administration',
  'backoffice',
  'staff',
  'superuser',
  'superadmin',
  'sysadmin',
  'moderator',
  'moderators',
  'management',
  'internal',
  'debug',
  'actuator',
  'console',
]);

const PARAM_SEGMENT = /[:{}<>*()?+[\]\\]/;

function segmentMatches(segment: string): boolean {
  const collapsed = segment.toLowerCase().replace(/[-_.]/g, '');
  return ADMIN_VOCABULARY.has(collapsed) || splitWords(segment).some((w) => ADMIN_VOCABULARY.has(w));
}

export function adminEvidence(route: { path: string; guardNames?: string[] }): string[] {
  const evidence: string[] = [];
  for (const segment of route.path.split('/')) {
    if (!segment || PARAM_SEGMENT.test(segment)) continue;
    if (segmentMatches(segment)) evidence.push(`admin-like: path segment "${segment}"`);
  }
  for (const name of route.guardNames ?? []) {
    if (splitWords(name).some((w) => ADMIN_VOCABULARY.has(w))) evidence.push(`middleware "${name}"`);
  }
  return evidence;
}
