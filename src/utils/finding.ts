/**
 * Single factory for Finding objects. Generates a stable id from the semantic
 * location so the same issue from different passes deduplicates cleanly.
 */
import * as crypto from 'crypto';
import type { Finding } from '../types';

export function makeFinding(f: Omit<Finding, 'id'>): Finding {
  const key = `${f.category}:${f.rule}:${f.file ?? ''}:${f.line ?? ''}:${f.endpoint ?? ''}`;
  const id = crypto.createHash('sha1').update(key).digest('hex').slice(0, 12);
  return { id, ...f };
}
