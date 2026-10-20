/**
 * Model output is untrusted. Before an AI finding is merged it is checked
 * against the real project (its `file` must be an existing regular file inside
 * the scanned root, file contents are never read), its model-suggested severity
 * is demoted to info (the suggestion stays visible in the description), and it
 * is labelled unverified so it can never affect the score or the CI gate.
 */
import * as fs from 'fs/promises';
import * as path from 'path';
import type { Finding } from '../types';

export interface VerifiedAiFindings {
  findings: Finding[];
  /** AI findings dropped because their `file` is not a real file inside the project. */
  dropped: number;
}

export async function verifyAiFindings(findings: Finding[], projectRoot: string): Promise<VerifiedAiFindings> {
  let realRoot: string | null = null;
  try {
    realRoot = await fs.realpath(path.resolve(projectRoot));
  } catch {
    realRoot = null;
  }

  const kept: Finding[] = [];
  let dropped = 0;
  for (const f of findings) {
    let file = f.file || undefined;
    if (file !== undefined) {
      const rel = realRoot ? await resolveInsideRoot(realRoot, file) : null;
      if (rel === null) {
        dropped++;
        continue;
      }
      file = rel;
    }
    kept.push({
      ...f,
      file,
      source: 'ai',
      severity: 'info',
      unverified: true,
      description: `AI-suggested severity: ${f.severity}. ${f.description}`.trim(),
    });
  }
  return { findings: kept, dropped };
}

export function droppedNote(dropped: number): string {
  return `${dropped} AI finding(s) dropped: referenced file not found`;
}

/** Returns the forward-slash path relative to root if `file` is an existing regular file inside it, else null. */
async function resolveInsideRoot(realRoot: string, file: string): Promise<string | null> {
  if (!file || file.includes('\0')) return null;
  if (path.isAbsolute(file) || path.win32.isAbsolute(file) || path.posix.isAbsolute(file)) return null;

  const lexical = path.resolve(realRoot, file);
  if (!isInside(realRoot, lexical)) return null;
  try {
    const real = await fs.realpath(lexical);
    if (!isInside(realRoot, real)) return null;
    if (!(await fs.stat(real)).isFile()) return null;
  } catch {
    return null;
  }
  return path.relative(realRoot, lexical).split(path.sep).join('/');
}

function isInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel !== '' && rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel);
}
