/**
 * Coverage: what a scan actually tested, per check area. Separate from findings on purpose: a
 * check that errored, was skipped or never ran must never read as "no issues found".
 *
 * The Orchestrator records each step's outcome in a CoverageRecorder (every catch/skip path sets a
 * state and a reason); buildCoverage() fills in the areas derived from the code graph (static rules
 * per language, secrets) and defaults every unrecorded area to `untested`.
 */
import * as path from 'path';
import { redact } from '../utils/redact';
import type { CoverageArea, CoverageKind, CoverageState, ScanReport } from '../types';

export interface CoverageEntry {
  state: CoverageState;
  reason: string;
  requested?: boolean;
}

const LABEL: Record<CoverageKind, string> = {
  static: 'static',
  secrets: 'secrets',
  dependencies: 'dependencies',
  'supabase-static': 'supabase (static)',
  'supabase-live': 'supabase (live)',
  firebase: 'firebase',
  dynamic: 'live',
  active: 'active/authz',
  ai: 'AI analysis',
};

const LIVE: ReadonlySet<CoverageKind> = new Set(['dynamic', 'active', 'supabase-live']);

/** Display order (static areas first). */
export const COVERAGE_KINDS: CoverageKind[] = [
  'static',
  'secrets',
  'dependencies',
  'dynamic',
  'active',
  'supabase-static',
  'supabase-live',
  'firebase',
  'ai',
];

const DEFAULTS: Record<Exclude<CoverageKind, 'static' | 'secrets'>, CoverageEntry> = {
  dependencies: {
    state: 'untested',
    reason: 'DeployReady does not audit dependencies in this release; run npm audit / pip-audit / composer audit.',
  },
  'supabase-static': { state: 'untested', reason: 'Supabase checks did not run.' },
  'supabase-live': { state: 'untested', reason: 'Opt-in (--supabase); not run.' },
  firebase: { state: 'untested', reason: 'Firebase checks did not run.' },
  dynamic: { state: 'untested', reason: 'Live (dynamic) checks did not run.' },
  active: { state: 'untested', reason: 'Opt-in (--active --token); not run.' },
  ai: { state: 'untested', reason: 'AI analysis did not run.' },
};

/** Collects step outcomes during a scan. Later calls for the same area overwrite earlier ones. */
export class CoverageRecorder {
  private readonly entries = new Map<CoverageKind, CoverageEntry>();

  set(kind: CoverageKind, state: CoverageState, reason: string, extra: { requested?: boolean } = {}): void {
    const prev = this.entries.get(kind);
    const requested = extra.requested ?? prev?.requested;
    // Reasons can carry error messages: redact before they reach any report.
    this.entries.set(kind, { state, reason: redact(reason), ...(requested !== undefined ? { requested } : {}) });
  }

  /** Downgrade a passed area (e.g. a sub-step of it failed). Never upgrades. */
  degrade(kind: CoverageKind, state: Exclude<CoverageState, 'passed'>, reason: string): void {
    const prev = this.entries.get(kind);
    if (!prev || prev.state === 'passed') this.set(kind, state, reason);
  }

  get(kind: CoverageKind): CoverageEntry | undefined {
    return this.entries.get(kind);
  }
}

const LANG_BY_EXT: Record<string, string> = {
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'javascript',
  '.tsx': 'javascript',
  '.py': 'python',
  '.php': 'php',
};
const LANG_LABEL: Record<string, string> = { javascript: 'JS/TS', python: 'Python', php: 'PHP' };

/** Languages the static rules ran on, from the parsed modules. */
export function scannedLanguages(report: Pick<ScanReport, 'graph'>): string[] {
  const langs = new Set<string>();
  for (const m of report.graph?.modules ?? []) {
    const lang = LANG_BY_EXT[path.extname(m.file).toLowerCase()];
    if (lang) langs.add(lang);
  }
  return [...langs].sort();
}

function area(kind: CoverageKind, e: CoverageEntry, id: string = kind, label: string = LABEL[kind]): CoverageArea {
  return {
    id,
    kind,
    label,
    state: e.state,
    reason: e.reason,
    ...(e.requested ? { requested: true } : {}),
    ...(LIVE.has(kind) ? { live: true } : {}),
  };
}

/** The coverage dimension of a report. Pure given the report and the recorded step outcomes. */
export function buildCoverage(report: Pick<ScanReport, 'graph'>, rec: CoverageRecorder = new CoverageRecorder()): CoverageArea[] {
  const out: CoverageArea[] = [];
  const staticEntry = rec.get('static');
  const langs = scannedLanguages(report);
  if (staticEntry && staticEntry.state !== 'passed') {
    out.push(area('static', staticEntry));
  } else if (langs.length === 0) {
    out.push(
      area('static', {
        state: 'untested',
        reason: 'No supported source files found (JS/TS, Python, PHP), so no static rule ran on application code.',
      }),
    );
  } else {
    for (const lang of langs) {
      out.push(area('static', { state: 'passed', reason: `Static rules ran on ${LANG_LABEL[lang] ?? lang} files.` }, `static-${lang}`, `static (${LANG_LABEL[lang] ?? lang})`));
    }
  }
  const secrets =
    rec.get('secrets') ??
    (staticEntry && staticEntry.state !== 'passed'
      ? { state: staticEntry.state, reason: `Runs with the static scan: ${staticEntry.reason}` }
      : (report.graph?.fileCount ?? 0) > 0 || langs.length > 0
        ? { state: 'passed' as const, reason: 'Secret detection ran on every scanned file.' }
        : { state: 'untested' as const, reason: 'No supported source files were scanned for secrets.' });
  out.push(area('secrets', secrets));
  for (const kind of COVERAGE_KINDS) {
    if (kind === 'static' || kind === 'secrets') continue;
    out.push(area(kind, rec.get(kind) ?? DEFAULTS[kind]));
  }
  return out;
}

const SYMBOL: Record<CoverageState, string> = {
  passed: '✓',
  failed: '✗ failed',
  untested: '– untested',
  inconclusive: '? inconclusive',
  'not-applicable': 'n/a',
};

/** Compact coverage list for one-line summaries. Static areas collapse to one entry; n/a areas are left out. */
export function coverageSummary(areas: CoverageArea[]): string {
  const parts: string[] = [];
  const statics = areas.filter((a) => a.kind === 'static');
  if (statics.length) {
    const worst = statics.find((a) => a.state !== 'passed');
    const langs = statics.filter((a) => a.id !== 'static').map((a) => a.label.replace(/^static \((.*)\)$/, '$1'));
    parts.push(`static${langs.length ? ` (${langs.join(', ')})` : ''} ${SYMBOL[worst ? worst.state : 'passed']}`);
  }
  for (const a of areas) {
    if (a.kind === 'static' || a.state === 'not-applicable') continue;
    parts.push(`${a.label} ${SYMBOL[a.state]}`);
  }
  return parts.join(' · ');
}

export function coverageSymbol(state: CoverageState): string {
  return SYMBOL[state];
}
