/**
 * Row-Level Security gap analysis for SQL migrations (Postgres / Supabase).
 *
 * Pure, no I/O. Finds, per table:
 *  - `missing`    created but RLS never enabled
 *  - `no-policy`  RLS enabled but no policy defined (denies ALL access)
 *  - `permissive` a policy that lets everyone through (`using (true)` etc.)
 *
 * Gating keeps us from nagging plain Postgres projects: `missing` only fires
 * when the project clearly exposes tables through a public API (Supabase —
 * `supabase: true`) or already enables RLS somewhere (it clearly intends to use
 * RLS and simply missed a table).
 */
export interface SqlFile {
  relPath: string;
  source: string;
}

export interface MissingRls {
  table: string;
  file: string;
  line: number;
}

export interface RlsOptions {
  /** The project is clearly Supabase / Postgres behind a public API. */
  supabase?: boolean;
}

export type RlsIssueKind = 'missing' | 'no-policy' | 'permissive';

export interface RlsIssue {
  kind: RlsIssueKind;
  table: string;
  file: string;
  line: number;
  /** True when the project enables RLS on at least one other table. */
  rlsUsedElsewhere: boolean;
  /** For `permissive`: the policy name and what is open. */
  policy?: string;
  command?: string;
  clause?: string;
}

const CREATE_TABLE_RE =
  /create\s+(?!temp(?:orary)?\b|unlogged\b)(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(?:["']?(\w+)["']?\.)?["']?(\w+)/gi;
const ENABLE_RLS_RE = /alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:["']?\w+["']?\.)?["']?(\w+)["']?\s+enable\s+row\s+level\s+security/gi;
const CREATE_POLICY_RE = /create\s+policy\s+(?:"([^"]+)"|(\w+))\s+on\s+(?:["']?\w+["']?\.)?["']?(\w+)["']?([^;]*)/gi;

/** Schemas Supabase does not expose through its public API. */
function isExposedSchema(schema: string | undefined): boolean {
  return !schema || schema.toLowerCase() === 'public';
}

function lineOf(source: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index; i++) if (source.charCodeAt(i) === 10) n++;
  return n;
}

/** Blank out `-- line comments` and block comments, preserving offsets and newlines. */
function stripComments(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/--[^\n]*/g, (m) => ' '.repeat(m.length));
}

function enabledTables(files: SqlFile[]): Set<string> {
  const set = new Set<string>();
  for (const f of files) {
    for (const m of stripComments(f.source).matchAll(ENABLE_RLS_RE)) set.add(m[1]!.toLowerCase());
  }
  return set;
}

export function analyzeRls(files: SqlFile[], opts: RlsOptions = {}): RlsIssue[] {
  const clean = files.map((f) => ({ relPath: f.relPath, source: stripComments(f.source) }));
  const enabled = enabledTables(files);
  const rlsUsedElsewhere = enabled.size > 0;
  const active = Boolean(opts.supabase) || rlsUsedElsewhere;
  const issues: RlsIssue[] = [];

  // Tables with at least one policy, and the policies themselves.
  const policied = new Set<string>();
  for (const f of clean) {
    for (const m of f.source.matchAll(CREATE_POLICY_RE)) {
      const table = m[3]!;
      policied.add(table.toLowerCase());
      const body = m[4] ?? '';
      const command = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(body)?.[1] ?? 'all').toLowerCase();
      const roles = /\bto\s+([^()]*?)(?=\s+(?:using|with)\b|$)/i.exec(body)?.[1]?.toLowerCase() ?? '';
      // Open to service_role only is harmless (that role bypasses RLS anyway).
      if (roles && /^\s*service_role\s*$/.test(roles)) continue;
      const usingTrue = /\busing\s*\(\s*true\s*\)/i.test(body);
      const checkTrue = /\bwith\s+check\s*\(\s*true\s*\)/i.test(body);
      // A world-readable SELECT is a common, deliberate choice; everything else is not.
      if ((usingTrue || checkTrue) && command !== 'select') {
        issues.push({
          kind: 'permissive',
          table,
          file: f.relPath,
          line: lineOf(f.source, m.index!),
          rlsUsedElsewhere,
          policy: m[1] ?? m[2],
          command,
          clause: usingTrue && checkTrue ? 'using (true) / with check (true)' : usingTrue ? 'using (true)' : 'with check (true)',
        });
      }
    }
  }

  if (active) {
    for (const f of clean) {
      for (const m of f.source.matchAll(CREATE_TABLE_RE)) {
        const table = m[2]!;
        if (!isExposedSchema(m[1])) continue;
        if (!enabled.has(table.toLowerCase())) {
          issues.push({ kind: 'missing', table, file: f.relPath, line: lineOf(f.source, m.index!), rlsUsedElsewhere });
        }
      }
    }
  }

  // RLS on but no policy: every request is denied. Safe, but almost always a bug.
  for (const f of clean) {
    for (const m of f.source.matchAll(ENABLE_RLS_RE)) {
      const table = m[1]!;
      if (!policied.has(table.toLowerCase())) {
        issues.push({ kind: 'no-policy', table, file: f.relPath, line: lineOf(f.source, m.index!), rlsUsedElsewhere });
        policied.add(table.toLowerCase()); // report once per table
      }
    }
  }
  return issues;
}

/** Tables created without RLS (kept for callers that only need that one check). */
export function tablesMissingRls(files: SqlFile[], opts: RlsOptions = {}): MissingRls[] {
  return analyzeRls(files, opts)
    .filter((i) => i.kind === 'missing')
    .map((i) => ({ table: i.table, file: i.file, line: i.line }));
}
