/**
 * Firebase static checks (no network): security rules, Realtime Database rules,
 * committed service-account keys, and firebase.json / .firebaserc detection.
 * The Firebase web config (apiKey, projectId, ...) is public by design and is
 * never reported here.
 */
import * as fs from 'fs/promises';
import * as path from 'path';
import { makeFinding, makeNote } from '../utils/finding';
import { isIgnored, parseGitignore, type IgnoreScope } from '../utils/GitIgnore';
import { scanFirebaseRules, scanRtdbRules } from './rules';
import { parseJsonLoose } from './rtdbParser';
import type { Finding } from '../types';

export interface SourceFile {
  relPath: string;
  source: string;
}

export interface FirebaseScan {
  findings: Finding[];
  /** True when firebase.json / .firebaserc / a rules file was found. */
  detected: boolean;
  /** User-facing lines (never contain secrets). */
  notes: string[];
}

const RTDB_NAME_RE = /(?:^|[.-])database[.-]rules\.json$/i;
const SERVICE_ACCOUNT_RE = /"type"\s*:\s*"service_account"/;
const PRIVATE_KEY_LINE_RE = /"private_key"\s*:\s*"[^"]*BEGIN [A-Z ]*PRIVATE KEY/;

export function isRulesFile(relPath: string): boolean {
  return /\.rules$/i.test(relPath);
}

/** Pure core: scan already-read files. */
export function scanFirebaseFiles(files: SourceFile[], ignored: (relPath: string) => boolean = () => false): FirebaseScan {
  const findings: Finding[] = [];
  const notes: string[] = [];
  let configured = false;
  let rulesSeen = false;
  const services: string[] = [];

  for (const f of files) {
    const base = path.posix.basename(f.relPath);
    if (base === 'firebase.json' || base === '.firebaserc') {
      configured = true;
      if (base === 'firebase.json') {
        const root = parseJsonLoose(f.source);
        if (root?.t === 'obj') {
          for (const k of ['firestore', 'storage', 'database', 'hosting', 'functions', 'emulators']) {
            if (root.entries.some((e) => e.key === k)) services.push(k);
          }
        }
      }
      continue;
    }
    if (isRulesFile(f.relPath)) {
      rulesSeen = true;
      findings.push(...scanFirebaseRules(f.relPath, f.source));
      continue;
    }
    if (!/\.json$/i.test(base)) continue;
    if (RTDB_NAME_RE.test(base)) {
      rulesSeen = true;
      findings.push(...scanRtdbRules(f.relPath, f.source));
      continue;
    }
    if (SERVICE_ACCOUNT_RE.test(f.source) && PRIVATE_KEY_LINE_RE.test(f.source) && !ignored(f.relPath)) {
      const line = f.source.split('\n').findIndex((l) => /"private_key"/.test(l)) + 1 || 1;
      findings.push(
        makeFinding({
          rule: 'firebase-service-account-committed',
          title: 'Firebase/Google service account key committed to the project',
          severity: 'critical',
          category: 'security',
          source: 'static',
          file: f.relPath,
          line,
          owasp: 'A02:2025',
          cwe: 'CWE-798',
          evidence: '"type": "service_account", "private_key": «REDACTED» (value withheld)',
          description:
            'This JSON file is a service account credential with its private key. It carries admin privileges (Firestore, Storage, Auth, ...) that bypass every security rule, and anyone who can read the repository or build output can use it.',
          recommendation:
            'Revoke the key now (Google Cloud Console > IAM > Service accounts > Keys > delete), create a new one only if you really need it, and load it at runtime from a secret store or the GOOGLE_APPLICATION_CREDENTIALS environment variable pointing outside the repo. Add the file to .gitignore and remove it from git history (git filter-repo).',
        }),
      );
    }
  }

  const detected = configured || rulesSeen;
  if (configured && !rulesSeen) {
    findings.push(
      makeNote({
        rule: 'firebase-no-rules-file',
        title: 'Firebase project detected but no security rules files found',
        category: 'security',
        source: 'static',
        file: 'firebase.json',
        description:
          'A Firebase config exists but no firestore.rules, storage.rules or database.rules.json is in the project, so the access rules deployed to your Firebase project could not be checked.',
        recommendation:
          'Keep rules in the repo (firebase init firestore / storage) and deploy them with the CLI so they can be reviewed, or review them in the Firebase console and make sure they are not test-mode rules.',
      }),
    );
  }
  if (configured) notes.push(`Firebase project detected${services.length ? ` (${[...new Set(services)].join(', ')})` : ''}. Rules are checked statically; live checks are not part of this release. See docs/FIREBASE.md.`);
  return { findings, detected, notes };
}

const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', 'out', 'coverage', 'vendor', '__pycache__', '.venv', 'venv', '.cache', '.next']);
const MAX_FILES = 20000;
const MAX_JSON_BYTES = 256 * 1024;
const MAX_RULES_BYTES = 1024 * 1024;

/** Walk the project and run the static checks. */
export async function scanFirebaseStatic(root: string): Promise<FirebaseScan> {
  const files: SourceFile[] = [];
  let scopes: IgnoreScope[] = [];
  try {
    scopes = [{ base: '', rules: parseGitignore(await fs.readFile(path.join(root, '.gitignore'), 'utf8')) }];
  } catch {
    /* no root .gitignore */
  }
  let count = 0;
  const walk = async (dir: string, rel: string): Promise<void> => {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (count >= MAX_FILES) return;
      const abs = path.join(dir, e.name);
      const relPath = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || e.name.startsWith('.git') || relPath === '.deployready') continue;
        await walk(abs, relPath);
        continue;
      }
      if (!e.isFile()) continue;
      const wanted = e.name === '.firebaserc' || /\.(?:rules|json)$/i.test(e.name);
      if (!wanted) continue;
      count++;
      try {
        const st = await fs.stat(abs);
        if (st.size > (isRulesFile(e.name) ? MAX_RULES_BYTES : MAX_JSON_BYTES)) continue;
        files.push({ relPath, source: await fs.readFile(abs, 'utf8') });
      } catch {
        /* unreadable: skip */
      }
    }
  };
  await walk(root, '');
  return scanFirebaseFiles(files, (p) => isIgnored(scopes, p, false));
}
