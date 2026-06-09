/**
 * Row-Level Security gap analysis for SQL migrations (Postgres / Supabase).
 *
 * Pure, no I/O. Finds tables that are CREATEd but never have RLS enabled — but
 * only when the project enables RLS *somewhere*, i.e. it clearly intends to use
 * RLS and simply missed a table. That gate keeps us from nagging projects that
 * don't use RLS at all (false positives).
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

const CREATE_TABLE_RE = /create\s+table\s+(?:if\s+not\s+exists\s+)?["']?(?:\w+\.)?["']?(\w+)/gi;
const ENABLE_RLS_RE = /alter\s+table\s+["']?(?:\w+\.)?["']?(\w+)["']?\s+enable\s+row\s+level\s+security/gi;

function enabledTables(files: SqlFile[]): Set<string> {
  const set = new Set<string>();
  for (const f of files) {
    for (const m of f.source.matchAll(ENABLE_RLS_RE)) set.add(m[1]!.toLowerCase());
  }
  return set;
}

export function tablesMissingRls(files: SqlFile[]): MissingRls[] {
  const enabled = enabledTables(files);
  if (enabled.size === 0) return []; // project doesn't use RLS — nothing to nag about
  const missing: MissingRls[] = [];

  for (const f of files) {
    const lines = f.source.split('\n');
    lines.forEach((line, i) => {
      for (const m of line.matchAll(CREATE_TABLE_RE)) {
        const table = m[1]!;
        if (!enabled.has(table.toLowerCase())) {
          missing.push({ table, file: f.relPath, line: i + 1 });
        }
      }
    });
  }
  return missing;
}
