/**
 * Project-level RLS settings, read from the scanned project (never from ~/.deployready):
 *
 *  - `.deployready.json` at the project root: `{ "publicTables": [...], "sensitiveTables": [...],
 *    "tenantColumns": [...], "exposedSchemas": [...] }` (also accepted under an `"rls"` key);
 *  - or the same object under a `"deployready"` key in the root package.json;
 *  - `supabase/config.toml` `[api] schemas = [...]` for the exposed schemas.
 *
 * Unknown keys and wrong types are ignored; a broken file never fails the scan.
 */
import * as fs from 'fs/promises';
import * as path from 'path';
import type { RlsProjectConfig } from './sensitivity';

const MAX_BYTES = 256 * 1024;

async function readSmall(file: string): Promise<string | null> {
  try {
    const st = await fs.stat(file);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    return await fs.readFile(file, 'utf8');
  } catch {
    return null;
  }
}

function strings(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out = v.filter((x): x is string => typeof x === 'string' && x.trim() !== '').map((x) => x.trim());
  return out.length ? out : undefined;
}

export function parseRlsConfig(raw: unknown): RlsProjectConfig {
  if (!raw || typeof raw !== 'object') return {};
  const o = raw as Record<string, unknown>;
  const src = o.rls && typeof o.rls === 'object' ? { ...o, ...(o.rls as Record<string, unknown>) } : o;
  const cfg: RlsProjectConfig = {};
  const pub = strings(src.publicTables);
  const sens = strings(src.sensitiveTables);
  const ten = strings(src.tenantColumns);
  const exp = strings(src.exposedSchemas);
  const pubB = strings(src.publicBuckets);
  const sensB = strings(src.sensitiveBuckets);
  if (pubB) cfg.publicBuckets = pubB;
  if (sensB) cfg.sensitiveBuckets = sensB;
  if (pub) cfg.publicTables = pub;
  if (sens) cfg.sensitiveTables = sens;
  if (ten) cfg.tenantColumns = ten;
  if (exp) cfg.exposedSchemas = exp;
  return cfg;
}

/** `[api] schemas = ["public", "graphql_public", "api"]` from supabase/config.toml (array may span lines). */
export function exposedSchemasFromToml(toml: string): string[] | undefined {
  const lines = toml.replace(/\r/g, '').split('\n');
  let section = '';
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.replace(/#.*$/, '').trim();
    const sec = /^\[([^\]]+)\]$/.exec(line);
    if (sec) {
      section = sec[1]!.trim();
      continue;
    }
    if (section !== 'api') continue;
    const m = /^schemas\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[1]!;
    while (!value.includes(']') && i + 1 < lines.length) value += lines[++i]!.replace(/#.*$/, '');
    const items = [...value.matchAll(/["']([^"']+)["']/g)].map((x) => x[1]!.trim()).filter(Boolean);
    return items.length ? items : undefined;
  }
  return undefined;
}

export async function loadRlsConfig(projectPath: string): Promise<RlsProjectConfig> {
  let cfg: RlsProjectConfig = {};
  const own = await readSmall(path.join(projectPath, '.deployready.json'));
  if (own !== null) {
    try {
      cfg = parseRlsConfig(JSON.parse(own));
    } catch {
      cfg = {};
    }
  } else {
    const pkg = await readSmall(path.join(projectPath, 'package.json'));
    if (pkg !== null) {
      try {
        cfg = parseRlsConfig((JSON.parse(pkg) as Record<string, unknown>).deployready);
      } catch {
        cfg = {};
      }
    }
  }
  if (!cfg.exposedSchemas) {
    const toml = await readSmall(path.join(projectPath, 'supabase', 'config.toml'));
    const schemas = toml ? exposedSchemasFromToml(toml) : undefined;
    if (schemas) cfg.exposedSchemas = schemas;
  }
  return cfg;
}
