/**
 * Row-Level Security analysis for SQL migrations (Postgres / Supabase).
 *
 * Pure, no I/O. The migrations are REPLAYED in order (`postgres/model.ts`) and only the final
 * state is judged, so a policy that was dropped, a table that was renamed or moved, or RLS that
 * was disabled and re-enabled is evaluated as it ends up — not as it once was.
 *
 * Per API-exposed table (schema `public` by default; see `exposedSchemas`):
 *  - `missing`    RLS never enabled (or the table was re-created / moved in without it)
 *  - `disabled`   an explicit DISABLE ROW LEVEL SECURITY is the final word on RLS
 *  - `no-policy`  RLS enabled but no policy (denies everything — safe, usually a bug)
 *  - `permissive` a permissive policy whose USING / WITH CHECK is TRUE for every row for anon or
 *                 for any signed-in user (`true`, `1 = 1`, `'a' = 'a'`, `auth.role() =
 *                 'authenticated'`, `auth.uid() is not null`, `x or true`, a subquery that
 *                 compares a column with itself, ...), not narrowed by a restrictive policy, on a
 *                 command the role holds a table privilege for.
 *
 * Severity follows data sensitivity (`postgres/sensitivity.ts`): an open read is critical on a
 * sensitive table, a warning ("review required") on an unknown one and not reported on a
 * public one; open writes are critical on sensitive tables and warnings elsewhere.
 *
 * `missing` stays gated as before: it only fires when the project is clearly Supabase or enables
 * RLS somewhere else, so plain Postgres projects are not nagged.
 */
import type { Role } from './postgres/expr';
import { replayMigrations, type DbModel, type PolicyCommand } from './postgres/model';
import { apiReachable, DEFAULT_EXPOSED, onlyNonApiRoles, openings, type Opening } from './postgres/access';
import { analyzeSupabaseObjects, type DeepIssue } from './postgres/deep';

export type { DeepIssue } from './postgres/deep';
import { classifyTable, type RlsProjectConfig, type Sensitivity } from './postgres/sensitivity';

export type { RlsProjectConfig } from './postgres/sensitivity';

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
  /** Project config: public / sensitive tables, tenant columns, exposed schemas. */
  config?: RlsProjectConfig;
}

export type RlsIssueKind = 'missing' | 'disabled' | 'no-policy' | 'permissive';
export type RlsSeverity = 'critical' | 'warning' | 'info';

export interface RlsIssue {
  kind: RlsIssueKind;
  /** Table name (unqualified, as it ends up after renames). */
  table: string;
  schema: string;
  file: string;
  line: number;
  severity: RlsSeverity;
  sensitivity: Sensitivity;
  sensitivityReason: string;
  /** True when the project enables RLS on at least one other table. */
  rlsUsedElsewhere: boolean;
  /** For `permissive`: the policy, the roles and commands it opens, and why. */
  policy?: string;
  command?: string;
  clause?: string;
  roles?: Role[];
  commands?: PolicyCommand[];
  /** True when only reads are open (the "is public read intended?" case). */
  readOnly?: boolean;
}

export function analyzeRls(files: SqlFile[], opts: RlsOptions = {}): RlsIssue[] {
  return analyzeRlsModel(replayMigrations(files), opts);
}

export interface SqlAnalysis {
  model: DbModel;
  rls: RlsIssue[];
  /** Storage, functions, views, triggers, Realtime and grant issues (`postgres/deep.ts`). */
  objects: DeepIssue[];
  /** Set when the object checks crashed (the RLS results still stand). */
  objectsError?: string;
}

/** Replay once, then run the RLS checks and the Supabase object checks on the same final state. */
export function analyzeSql(files: SqlFile[], opts: RlsOptions = {}): SqlAnalysis {
  const model = replayMigrations(files);
  const rls = analyzeRlsModel(model, opts);
  try {
    return { model, rls, objects: analyzeSupabaseObjects(model, { config: opts.config, supabase: opts.supabase }) };
  } catch (err) {
    return { model, rls, objects: [], objectsError: (err as Error).message || 'object checks failed' };
  }
}

export function analyzeRlsModel(model: DbModel, opts: RlsOptions = {}): RlsIssue[] {
  const cfg = opts.config ?? {};
  const exposed = new Set((cfg.exposedSchemas ?? DEFAULT_EXPOSED).map((s) => s.trim().replace(/"/g, '')));
  const rlsUsedElsewhere = model.rlsUsed;
  const gate = Boolean(opts.supabase) || rlsUsedElsewhere;
  const issues: RlsIssue[] = [];

  for (const t of model.tables.values()) {
    if (!exposed.has(t.schema)) continue;
    const verdict = classifyTable(t, cfg);
    const base = {
      table: t.name,
      schema: t.schema,
      sensitivity: verdict.level,
      sensitivityReason: verdict.reason,
      rlsUsedElsewhere,
    };

    if (!t.rls) {
      if (t.rlsUncertain || !apiReachable(t)) continue;
      const severity: RlsSeverity = verdict.level === 'sensitive' ? 'critical' : 'warning';
      if (t.disabledAt) {
        issues.push({ ...base, kind: 'disabled', file: t.disabledAt.file, line: t.disabledAt.line, severity: 'critical' });
      } else if (gate && !t.stub) {
        issues.push({ ...base, kind: 'missing', file: t.loc.file, line: t.loc.line, severity });
      }
      continue;
    }

    if (t.policies.size === 0) {
      issues.push({ ...base, kind: 'no-policy', file: t.loc.file, line: t.loc.line, severity: 'info' });
      continue;
    }

    // Group what each permissive policy opens.
    const byPolicy = new Map<string, Opening[]>();
    for (const o of openings(model, t)) {
      if (onlyNonApiRoles(o.policy)) continue;
      const list = byPolicy.get(o.policy.name) ?? [];
      list.push(o);
      byPolicy.set(o.policy.name, list);
    }
    for (const [name, list] of byPolicy) {
      const p = list[0]!.policy;
      const reads = list.filter((o) => o.cmd === 'select');
      const writes = list.filter((o) => o.cmd !== 'select');
      let severity: RlsSeverity | null = null;
      if (verdict.level === 'sensitive') severity = 'critical';
      else if (writes.length > 0) severity = 'warning';
      else if (verdict.level === 'unknown') severity = 'warning';
      if (!severity) continue; // a public table that is only readable: intended
      const relevant = verdict.level === 'public' ? writes : list;
      const roles = [...new Set(relevant.map((o) => o.role))];
      const commands = [...new Set(relevant.map((o) => o.cmd))];
      issues.push({
        ...base,
        kind: 'permissive',
        file: p.loc.file,
        line: p.loc.line,
        severity,
        policy: name,
        command: p.command,
        clause: relevant[0]!.why,
        roles,
        commands,
        readOnly: commands.every((c) => c === 'select'),
      });
    }
  }
  return issues.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

/** Tables created without RLS (kept for callers that only need that one check). */
export function tablesMissingRls(files: SqlFile[], opts: RlsOptions = {}): MissingRls[] {
  return analyzeRls(files, opts)
    .filter((i) => i.kind === 'missing')
    .map((i) => ({ table: i.table, file: i.file, line: i.line }));
}
