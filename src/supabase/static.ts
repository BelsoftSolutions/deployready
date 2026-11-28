/**
 * Static (no network) Supabase checks. Name-based detection (the string
 * `service_role`, secret-named NEXT_PUBLIC_/VITE_ vars) belongs to the
 * `supabase-service-role` rule in analysis/rules.ts; this file only adds what
 * needs the key itself:
 *   - a key LITERAL whose decoded JWT `role` claim is service_role (or an
 *     sb_secret_ key) in client-side code ("use client" files; src/, app/,
 *     components/ in a Vite app);
 *   - a public-prefixed env var (NEXT_PUBLIC_, VITE_, …) whose VALUE decodes to a
 *     service_role key, whatever the var is called — the framework ships it to
 *     every browser;
 * and detects the project's Supabase URL, anon key and migration tables for the
 * live checks. Key values never leave this file unredacted.
 */
import * as fs from 'fs/promises';
import * as path from 'path';
import { FileWalker, isEnvFile } from '../utils/FileWalker';
import { makeFinding } from '../utils/finding';
import { redact } from '../utils/redact';
import { classifyKey, JWT_RE, SB_PUBLISHABLE_RE, SB_SECRET_RE, projectRefFromUrl } from './keys';
import { analyzeEdgeFunctions, parseFunctionsToml } from './edgeFunctions';
import type { Finding } from '../types';

export interface DetectedSupabase {
  url?: string;
  /** Where the URL was found (relative path). */
  urlSource?: string;
  anonKey?: string;
  anonKeySource?: string;
  /** Tables created in local SQL migrations (fallback table list for live checks). */
  migrationTables: string[];
  /** SQL files under a supabase/ directory. */
  sqlFiles?: number;
  /** supabase/config.toml files read. */
  configFiles?: number;
}

export interface EdgeFunctionCoverage {
  /** verify_jwt = false functions whose code was read and checked. */
  checked: number;
  /** verify_jwt = false functions whose entrypoint was not in the project. */
  missing: string[];
  /** The Edge Function check crashed. */
  error?: string;
}

export interface StaticResult {
  findings: Finding[];
  detected: DetectedSupabase;
  edgeFunctions?: EdgeFunctionCoverage;
  /** The project's SQL files (for the drift comparison). */
  sql?: SourceFile[];
}

export interface SourceFile {
  relPath: string;
  source: string;
}

const PUBLIC_PREFIX_RE = /^(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|GATSBY_)/;
const ENV_LINE_RE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?([^'"#\s]*)/;
const SUPABASE_URL_RE = /https:\/\/[a-z0-9]{10,40}\.supabase\.(?:co|in)\b/;
const CREATE_TABLE_RE = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?([A-Za-z_][A-Za-z0-9_]*)"?\s*\(/gi;
const SERVER_PATH_RE =
  /(?:^|\/)(?:api|server|servers|functions|supabase|scripts|migrations|lib\/server|middleware)(?:\/|$)|\.server\.[cm]?[jt]sx?$|(?:^|\/)route\.[cm]?[jt]s$|(?:^|\/)middleware\.[cm]?[jt]s$/;
const CODE_EXT_RE = /\.(?:[cm]?[jt]sx?|vue|svelte)$/;
const USE_CLIENT_RE = /^\s*(?:(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/)\s*)*['"]use client['"]/;

const OWASP = 'A02:2025';
const CWE = 'CWE-200';

/** Evidence-safe text: masks the new-format keys (not covered by redact) then redacts. */
export function safeEvidence(text: string): string {
  const masked = text
    .replace(new RegExp(SB_SECRET_RE.source, 'g'), '«REDACTED»')
    .replace(new RegExp(SB_PUBLISHABLE_RE.source, 'g'), '«REDACTED»');
  return redact(masked).trim().slice(0, 200);
}

export function isViteProject(files: SourceFile[]): boolean {
  return files.some(
    (f) =>
      /(?:^|\/)vite\.config\.[cm]?[jt]s$/.test(f.relPath) ||
      (/(?:^|\/)package\.json$/.test(f.relPath) && /"vite"\s*:/.test(f.source)),
  );
}

/** Is this file shipped to the browser? Conservative: only clear signals count. */
export function isClientFile(relPath: string, source: string, vite: boolean): boolean {
  if (!CODE_EXT_RE.test(relPath)) return false;
  if (SERVER_PATH_RE.test(relPath)) return false;
  if (USE_CLIENT_RE.test(source)) return true;
  return vite && /^(?:src|app|components)\//.test(relPath);
}

function hasServiceKeyLiteral(line: string): boolean {
  if (SB_SECRET_RE.test(line)) return true;
  for (const m of line.matchAll(JWT_RE)) {
    if (classifyKey(m[0]).kind === 'service_role') return true;
  }
  return false;
}

/** Pure core: scan already-read files (supabase/config.toml files may be among them). */
export function scanSupabaseFiles(files: SourceFile[]): StaticResult {
  const findings: Finding[] = [];
  const detected: DetectedSupabase = { migrationTables: [] };
  const seen = new Set<string>();
  const vite = isViteProject(files);
  const tables = new Set<string>();

  const add = (rule: string, title: string, f: SourceFile, line: number, text: string, description: string): void => {
    const key = `${rule}:${f.relPath}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(
      makeFinding({
        rule,
        title,
        severity: 'critical',
        category: 'security',
        source: 'static',
        file: f.relPath,
        line,
        owasp: OWASP,
        cwe: CWE,
        evidence: safeEvidence(text),
        description,
        recommendation:
          'Rotate the service_role / secret key in the Supabase dashboard (Project Settings → API) now, then use it only in server-side code (API routes, server actions, Edge Functions) read from a non-public env var. The browser should only ever get the anon / publishable key, with RLS policies doing the access control.',
      }),
    );
  };

  const noteUrl = (url: string, src: string): void => {
    if (!detected.url) {
      detected.url = url;
      detected.urlSource = src;
    }
  };
  const noteAnon = (key: string, src: string): void => {
    if (classifyKey(key).kind !== 'anon') return;
    if (!detected.anonKey) {
      detected.anonKey = key;
      detected.anonKeySource = src;
    }
  };

  for (const f of files) {
    const base = path.posix.basename(f.relPath);
    const lines = f.source.split('\n');

    if (/\.sql$/i.test(f.relPath)) {
      for (const m of f.source.matchAll(CREATE_TABLE_RE)) tables.add(m[1]!);
      if (/(?:^|\/)supabase\//.test(f.relPath)) detected.sqlFiles = (detected.sqlFiles ?? 0) + 1;
      continue;
    }
    if (TOML_RE.test(f.relPath)) continue;

    if (isEnvFile(base)) {
      lines.forEach((raw, i) => {
        const m = ENV_LINE_RE.exec(raw);
        if (!m) return;
        const [, name, value] = m as unknown as [string, string, string];
        if (!value) return;
        const kind = classifyKey(value).kind;
        if (PUBLIC_PREFIX_RE.test(name) && kind === 'service_role') {
          add(
            'supabase-service-jwt-public-env',
            `Supabase service_role key in public env var ${name}`,
            f,
            i + 1,
            `${name}=«REDACTED»`,
            `${name} is a public (browser-exposed) env var and its value is a service_role key (decoded role claim / sb_secret_ key). Frameworks inline public-prefixed vars into the client bundle, so anyone visiting the site can read it and bypass every RLS policy.`,
          );
        }
        if (/SUPABASE_URL$/.test(name) && /^https?:\/\//.test(value)) noteUrl(value, f.relPath);
        if (/SUPABASE_(?:ANON|PUBLISHABLE)(?:_KEY)?$/.test(name) || /SUPABASE_KEY$/.test(name)) noteAnon(value, f.relPath);
      });
      continue;
    }

    if (!CODE_EXT_RE.test(f.relPath)) continue;
    const client = isClientFile(f.relPath, f.source, vite);
    lines.forEach((line, i) => {
      if (line.length > 4000) return;
      const url = SUPABASE_URL_RE.exec(line);
      if (url) noteUrl(url[0], f.relPath);
      for (const m of line.matchAll(JWT_RE)) noteAnon(m[0], f.relPath);
      const pub = SB_PUBLISHABLE_RE.exec(line);
      if (pub) noteAnon(pub[0], f.relPath);

      if (!client) return;
      if (hasServiceKeyLiteral(line)) {
        add(
          'supabase-service-jwt-client',
          'Supabase service_role key literal in client-side code',
          f,
          i + 1,
          line,
          `${f.relPath} runs in the browser (${USE_CLIENT_RE.test(f.source) ? '"use client"' : 'Vite client source'}) and contains a key whose decoded role is service_role (or an sb_secret_ key). That key bypasses Row-Level Security, so anyone can read or modify every table.`,
        );
      }
    });
  }

  // Prefer an anon key that belongs to the detected project.
  const ref = projectRefFromUrl(detected.url);
  const anonRef = classifyKey(detected.anonKey).ref;
  if (ref && anonRef && ref !== anonRef) {
    delete detected.anonKey;
    delete detected.anonKeySource;
  }
  detected.migrationTables = [...tables];
  const edgeFunctions = edgeFunctionChecks(files, findings);
  if (edgeFunctions.configs) detected.configFiles = edgeFunctions.configs;
  return { findings, detected, edgeFunctions: edgeFunctions.coverage, sql: files.filter((f) => /\.sql$/i.test(f.relPath)) };
}

const TOML_RE = /(?:^|\/)supabase\/config\.toml$/;

/** `verify_jwt = false` Edge Functions, per supabase/config.toml. Never throws: a crash is reported in the coverage. */
function edgeFunctionChecks(files: SourceFile[], findings: Finding[]): { coverage: EdgeFunctionCoverage; configs: number } {
  const coverage: EdgeFunctionCoverage = { checked: 0, missing: [] };
  let configs = 0;
  try {
    for (const toml of files.filter((f) => TOML_RE.test(f.relPath))) {
      configs++;
      const r = analyzeEdgeFunctions(toml.relPath, parseFunctionsToml(toml.source), files);
      findings.push(...r.findings);
      coverage.checked += r.checked;
      coverage.missing.push(...r.missing);
    }
  } catch (err) {
    coverage.error = (err as Error).message || 'Edge Function check failed';
  }
  return { coverage, configs };
}

/** Walk the project and run the static checks. */
export async function scanSupabaseStatic(root: string): Promise<StaticResult> {
  const walked = await FileWalker.walk(root);
  const files: SourceFile[] = [];
  for (const w of walked) {
    try {
      files.push({ relPath: w.relPath, source: await fs.readFile(w.absPath, 'utf8') });
    } catch {
      /* unreadable file: skip */
    }
  }
  // supabase/config.toml is not a source file for the walker: read it (and any next to an Edge Function) directly.
  const dirs = new Set<string>(['supabase']);
  for (const f of files) {
    const m = /^(.*?(?:^|\/)supabase)\/functions\//.exec(f.relPath);
    if (m) dirs.add(m[1]!);
  }
  for (const d of dirs) {
    const rel = `${d}/config.toml`;
    if (files.some((f) => f.relPath === rel)) continue;
    try {
      const abs = path.join(root, ...rel.split('/'));
      const st = await fs.stat(abs);
      if (st.isFile() && st.size <= 512 * 1024) files.push({ relPath: rel, source: await fs.readFile(abs, 'utf8') });
    } catch {
      /* no config.toml */
    }
  }
  return scanSupabaseFiles(files);
}
