/**
 * Rules test plan: turns the `match` / `allow` structure of firestore.rules and
 * storage.rules into concrete, emulator-testable targets (one per match path).
 * Pure: no I/O.
 */
import { parseRules, inlineFunctions, type AllowStatement } from '../rulesParser';
import { isUserOwnedPath } from '../rules';

export const OWNER_UID = 'alice';
export const OTHER_UID = 'bob';
export const MAX_TARGETS = 40;

export type FbService = 'firestore' | 'storage';

export interface ProbeTarget {
  service: FbService;
  /** Rules file, relative to the project root. */
  file: string;
  /** Path as written in the rules, minus the database/bucket prefix, e.g. /users/{userId}. */
  display: string;
  /** Concrete document path (Firestore) or object name (Storage) used for the probes. */
  docPath: string;
  /** Firestore: parent collection of docPath. Storage: directory prefix of the object. */
  collectionPath: string;
  /** Fields set to the owner's uid in seeded/created documents (taken from the rules' own conditions). */
  ownerFields: string[];
  recursive: boolean;
  userOwned: boolean;
  allows: AllowStatement[];
  /** Lines of the `allow` statements for this path. */
  lines: number[];
}

export interface RulesInput {
  relPath: string;
  source: string;
}

export interface Plan {
  targets: ProbeTarget[];
  /** Paths that could not be turned into a probe, each with the reason. */
  skipped: string[];
}

const FS_PREFIX = /^\/databases\/\{[^}]*\}\/documents/;
const ST_PREFIX = /^\/b\/\{[^}]*\}\/o/;
const VAR_RE = /^\{([A-Za-z_]\w*)(=\*\*)?\}$/;

function ownerFieldsFrom(source: string): string[] {
  const out = new Set<string>();
  for (const m of source.matchAll(/\b(?:resource|request\.resource)\.data\.([A-Za-z_]\w*)/g)) out.add(m[1]!);
  for (const m of source.matchAll(/\b(?:resource|request\.resource)\.data\[\s*['"]([A-Za-z_]\w*)['"]\s*\]/g)) out.add(m[1]!);
  if (out.size === 0) out.add('ownerId');
  return [...out].slice(0, 12);
}

/** Build the plan for one rules file. */
export function planRulesFile(file: RulesInput): Plan {
  const parsed = parseRules(file.source);
  const service: FbService | undefined =
    parsed.service === 'firestore' ? 'firestore' : parsed.service === 'storage' ? 'storage' : /storage\.rules$/i.test(file.relPath) ? 'storage' : /firestore\.rules$/i.test(file.relPath) ? 'firestore' : undefined;
  if (!service) return { targets: [], skipped: [`${file.relPath}: unknown rules service`] };
  const prefix = service === 'firestore' ? FS_PREFIX : ST_PREFIX;
  const ownerFields = ownerFieldsFrom(file.source);

  const byPath = new Map<string, AllowStatement[]>();
  for (const a of parsed.allows) {
    const list = byPath.get(a.path) ?? [];
    list.push(a);
    byPath.set(a.path, list);
  }

  const targets: ProbeTarget[] = [];
  const skipped: string[] = [];
  for (const [full, allows] of byPath) {
    const display = full.replace(prefix, '') || '/';
    const segs = display.split('/').filter(Boolean);
    const condText = allows.map((a) => (a.condition ? inlineFunctions(a.condition, parsed.functions) : '') + ' ' + (a.condition ?? '')).join(' ');
    let fixed = 0;
    const out: string[] = [];
    let bad = false;
    for (const s of segs) {
      const v = VAR_RE.exec(s);
      if (!v) {
        if (/[{}$]/.test(s)) bad = true;
        out.push(s);
        fixed++;
      } else if (v[2]) {
        // Recursive wildcard: Firestore needs an even number of segments for a document.
        const n = service === 'firestore' ? (out.length % 2 === 0 ? 2 : 1) : 1;
        for (let i = 0; i < n; i++) out.push(service === 'firestore' ? (i === 0 && n === 2 ? 'dr-col' : 'dr-doc') : 'dr-obj.txt');
      } else {
        out.push(new RegExp(`\\b${v[1]}\\b`).test(condText) ? OWNER_UID : `dr-${v[1]}`);
        fixed++;
      }
    }
    void fixed;
    if (bad) { skipped.push(`${file.relPath} ${display}: path not understood`); continue; }
    if (out.length === 0) { skipped.push(`${file.relPath} ${display}: no concrete path`); continue; }
    if (service === 'firestore' && out.length % 2 !== 0) { skipped.push(`${file.relPath} ${display}: collection-level match without a document wildcard`); continue; }
    const recursive = allows.some((a) => a.recursive);
    targets.push({
      service,
      file: file.relPath,
      display,
      docPath: out.join('/'),
      collectionPath: service === 'firestore' ? out.slice(0, -1).join('/') : out.slice(0, -1).join('/') + (out.length > 1 ? '/' : ''),
      ownerFields,
      recursive,
      userOwned: isUserOwnedPath(full),
      allows,
      lines: allows.map((a) => a.line),
    });
  }
  return { targets, skipped };
}

export function buildPlan(files: RulesInput[]): Plan {
  const targets: ProbeTarget[] = [];
  const skipped: string[] = [];
  for (const f of files) {
    const p = planRulesFile(f);
    targets.push(...p.targets);
    skipped.push(...p.skipped);
  }
  if (targets.length > MAX_TARGETS) {
    skipped.push(`${targets.length - MAX_TARGETS} further path(s) not tested (limit ${MAX_TARGETS})`);
    targets.length = MAX_TARGETS;
  }
  return { targets, skipped };
}
