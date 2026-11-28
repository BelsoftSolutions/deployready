/**
 * Who can reach which rows of a replayed table: privileges, permissive / restrictive policies and
 * the always-true classification of their clauses. Shared by the RLS checks (`../rls.ts`) and the
 * Supabase object checks (`deep.ts`).
 */
import { alwaysTrueFor, findSelfCompares, type ColumnLookup, type Role } from './expr';
import { tableKey, type DbModel, type PolicyCommand, type PolicyState, type Privilege, type TableState } from './model';

export const DEFAULT_EXPOSED = ['public', 'graphql_public'];
export const ROLES: Role[] = ['anon', 'authenticated'];
export const COMMANDS: Exclude<PolicyCommand, 'all'>[] = ['select', 'insert', 'update', 'delete'];
/** Roles that bypass RLS or are not reachable through the API: policies only for them never expose data. */
export const NON_API_ROLES = new Set(['service_role', 'postgres', 'supabase_admin', 'supabase_auth_admin', 'supabase_storage_admin', 'dashboard_user']);

export function appliesTo(p: PolicyState, role: Role): boolean {
  return p.roles.some((r) => r === 'public' || r === role);
}

export function coversCommand(p: PolicyState, cmd: Exclude<PolicyCommand, 'all'>): boolean {
  return p.command === 'all' || p.command === cmd;
}

/** The expression that decides access for `cmd`: USING for reads / existing rows, WITH CHECK for new rows. */
export function clauseFor(p: PolicyState, cmd: Exclude<PolicyCommand, 'all'>): { expr: PolicyState['using']; text: string; label: 'using' | 'with check'; present: boolean } {
  if (cmd === 'insert') {
    if (p.hasCheck) return { expr: p.check, text: p.checkText, label: 'with check', present: true };
    // FOR ALL without WITH CHECK reuses USING for new rows
    if (p.command === 'all' && p.hasUsing) return { expr: p.using, text: p.usingText, label: 'using', present: true };
    return { expr: null, text: '', label: 'with check', present: false };
  }
  return { expr: p.using, text: p.usingText, label: 'using', present: p.hasUsing };
}

export function hasPrivilege(t: TableState, role: Role, cmd: Privilege): boolean {
  if (t.grants.get(role)?.has(cmd) || t.grants.get('public')?.has(cmd)) return true;
  // Column-level INSERT / UPDATE still lets the role write rows; column-level SELECT is judged by
  // the column-grant check instead (it is how Supabase projects hide columns on purpose).
  return cmd !== 'select' && t.columnGrants.some((g) => (g.role === role || g.role === 'public') && g.priv === cmd);
}

export function apiReachable(t: TableState): boolean {
  return ROLES.some((r) => COMMANDS.some((c) => hasPrivilege(t, r, c)));
}

export function columnLookup(model: DbModel, schemaHint: string): ColumnLookup {
  return (name, col) => {
    const schema = name.length >= 2 ? name[name.length - 2]! : schemaHint;
    const t = model.tables.get(tableKey(schema, name[name.length - 1]!)) ?? (name.length < 2 ? model.tables.get(tableKey('public', name[0]!)) : undefined);
    if (!t?.columns) return null;
    return t.columns.has(col);
  };
}

export interface Opening {
  policy: PolicyState;
  role: Role;
  cmd: Exclude<PolicyCommand, 'all'>;
  why: string;
}

/** Why `p` lets `role` through on every row, or null. */
export function openReason(model: DbModel, t: TableState, p: PolicyState, role: Role, cmd: Exclude<PolicyCommand, 'all'>): string | null {
  const cl = clauseFor(p, cmd);
  if (!cl.present) return null;
  if (alwaysTrueFor(cl.expr, { role })) return `${cl.label} (${cl.text})`;
  if (role === 'authenticated') {
    const self = findSelfCompares(cl.expr, columnLookup(model, t.schema));
    if (self.length) {
      return `${cl.label} (${cl.text}): \`${self[0]!.text}\` compares ${self[0]!.column} with itself (the unqualified column resolves to the subquery's own table), so the subquery is true for every row`;
    }
  }
  return null;
}

/** Restrictive policies that apply must all be TRUE too; one we cannot prove true closes the gap. */
export function restrictedAway(t: TableState, role: Role, cmd: Exclude<PolicyCommand, 'all'>): boolean {
  for (const q of t.policies.values()) {
    if (q.permissive || !appliesTo(q, role) || !coversCommand(q, cmd)) continue;
    const cl = clauseFor(q, cmd);
    if (!cl.present) continue;
    if (!alwaysTrueFor(cl.expr, { role })) return true;
  }
  return false;
}

export function openings(model: DbModel, t: TableState): Opening[] {
  const out: Opening[] = [];
  for (const role of ROLES)
    for (const cmd of COMMANDS) {
      if (!hasPrivilege(t, role, cmd)) continue;
      if (restrictedAway(t, role, cmd)) continue;
      for (const p of t.policies.values()) {
        if (!p.permissive || !appliesTo(p, role) || !coversCommand(p, cmd)) continue;
        const why = openReason(model, t, p, role, cmd);
        if (why) out.push({ policy: p, role, cmd, why });
      }
    }
  return out;
}

export function onlyNonApiRoles(p: PolicyState): boolean {
  return p.roles.length > 0 && p.roles.every((r) => NON_API_ROLES.has(r));
}

