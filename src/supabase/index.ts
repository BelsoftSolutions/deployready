/**
 * Supabase module entry point: static checks always (no network); live checks
 * only with --supabase, behind the ownership gate (guard.ts) and a consent
 * prompt (skipped by --yes). Credentials come from flags or env vars and are
 * never printed.
 */
import inquirer from 'inquirer';
import { logger } from '../utils/logger';
import { redact } from '../utils/redact';
import { SupabaseHttp, type Transport } from './http';
import { checkOwnership } from './guard';
import { classifyKey, normalizeProjectUrl, projectRefFromUrl } from './keys';
import { runLiveChecks, type TestUser } from './live';
import { scanSupabaseStatic, type DetectedSupabase } from './static';
import type { Finding } from '../types';

export interface SupabaseOptions {
  /** Run the live (network) checks. */
  live?: boolean;
  url?: string;
  anonKey?: string;
  serviceKey?: string;
  accessToken?: string;
  /** Opt-in two-user cross-read test (users from env). */
  crossUser?: boolean;
  /** Minimum ms between requests (default 250). */
  delayMs?: number;
}

export interface Credentials {
  url?: string;
  anonKey?: string;
  serviceKey?: string;
  accessToken?: string;
  users?: { a: TestUser; b: TestUser };
}

export interface SupabaseRunDeps {
  env?: NodeJS.ProcessEnv;
  transport?: Transport;
  managementTransport?: Transport;
  /** Asked once ownership is proven, before any data-plane request. */
  confirm?: (target: string, mode: string) => Promise<boolean>;
}

export interface SupabaseRunResult {
  staticFindings: Finding[];
  liveFindings: Finding[];
  /** User-facing lines (never contain secrets). */
  notes: string[];
  /** True when live checks were requested but the ownership gate refused. */
  refused?: boolean;
}

export const ENV = {
  url: 'SUPABASE_URL',
  anonKey: 'SUPABASE_ANON_KEY',
  serviceKey: 'SUPABASE_SERVICE_ROLE_KEY',
  accessToken: 'SUPABASE_ACCESS_TOKEN',
  userAEmail: 'SUPABASE_TEST_USER_A_EMAIL',
  userAPassword: 'SUPABASE_TEST_USER_A_PASSWORD',
  userBEmail: 'SUPABASE_TEST_USER_B_EMAIL',
  userBPassword: 'SUPABASE_TEST_USER_B_PASSWORD',
} as const;

/** Flags win over env vars, which win over what the static scan found in the project. */
export function resolveCredentials(
  opts: SupabaseOptions,
  env: NodeJS.ProcessEnv,
  detected: DetectedSupabase,
): Credentials {
  const pick = (...v: (string | undefined)[]): string | undefined => v.find((x) => x && x.trim())?.trim();
  const creds: Credentials = {
    url: pick(opts.url, env[ENV.url], detected.url),
    anonKey: pick(opts.anonKey, env[ENV.anonKey], detected.anonKey),
    serviceKey: pick(opts.serviceKey, env[ENV.serviceKey]),
    accessToken: pick(opts.accessToken, env[ENV.accessToken]),
  };
  const ae = env[ENV.userAEmail];
  const ap = env[ENV.userAPassword];
  const be = env[ENV.userBEmail];
  const bp = env[ENV.userBPassword];
  if (ae && ap && be && bp) creds.users = { a: { email: ae, password: ap }, b: { email: be, password: bp } };
  return creds;
}

export async function runSupabase(
  projectPath: string,
  opts: SupabaseOptions,
  deps: SupabaseRunDeps = {},
): Promise<SupabaseRunResult> {
  const notes: string[] = [];
  const { findings: staticFindings, detected } = await scanSupabaseStatic(projectPath);
  const result: SupabaseRunResult = { staticFindings, liveFindings: [], notes };

  if (!opts.live) {
    if (detected.url) {
      notes.push(
        `Supabase project detected (${detected.urlSource}). Run with --supabase to prove what the anon key can read (read-only; needs proof you own the project). See docs/SUPABASE.md.`,
      );
    }
    return result;
  }

  const creds = resolveCredentials(opts, deps.env ?? process.env, detected);
  if (!creds.url) {
    notes.push(`Supabase live checks skipped: no project URL (set ${ENV.url} or --supabase-url).`);
    return result;
  }
  let origin: string;
  try {
    origin = normalizeProjectUrl(creds.url);
  } catch {
    notes.push('Supabase live checks skipped: the project URL is not a valid URL.');
    return result;
  }
  if (!creds.anonKey) {
    notes.push(`Supabase live checks skipped: no anon key (set ${ENV.anonKey} or --supabase-anon-key).`);
    return result;
  }
  const anonInfo = classifyKey(creds.anonKey);
  const ref = projectRefFromUrl(origin);
  if (anonInfo.kind === 'service_role') {
    notes.push('Supabase live checks skipped: the anon key given is actually a service_role key. Pass the public anon key as the anon key.');
    return result;
  }
  if (anonInfo.ref && ref && anonInfo.ref !== ref) {
    notes.push('Supabase live checks skipped: the anon key belongs to a different project than the URL.');
    return result;
  }

  let http: SupabaseHttp;
  try {
    http = new SupabaseHttp({ origin, transport: deps.transport, minIntervalMs: opts.delayMs });
  } catch (err) {
    notes.push(`Supabase live checks skipped: ${(err as Error).message}`);
    return result;
  }

  const gate = await checkOwnership(
    { url: origin, serviceKey: creds.serviceKey, accessToken: creds.accessToken },
    { project: http, managementTransport: deps.managementTransport, minIntervalMs: opts.delayMs },
  );
  if (!gate.allowed) {
    notes.push(`Supabase live checks refused. ${gate.reason}`);
    result.refused = true;
    return result;
  }
  notes.push(`Supabase ownership: ${gate.reason}`);

  if (deps.confirm && !(await deps.confirm(origin, gate.mode ?? ''))) {
    notes.push('Skipping Supabase live checks by your choice.');
    return result;
  }

  let crossUser: { a: TestUser; b: TestUser } | undefined;
  if (opts.crossUser) {
    if (creds.users) crossUser = creds.users;
    else
      notes.push(
        `Cross-user test skipped: set ${ENV.userAEmail}, ${ENV.userAPassword}, ${ENV.userBEmail} and ${ENV.userBPassword} (two test accounts you own).`,
      );
  }

  // A service key is only used once the gate has validated it for this project.
  const serviceKey = gate.mode === 'service-role' || gate.mode === 'local' ? creds.serviceKey : undefined;
  const live = await runLiveChecks({
    http,
    anonKey: creds.anonKey,
    serviceKey: serviceKey && classifyKey(serviceKey).kind === 'service_role' ? serviceKey : undefined,
    fallbackTables: detected.migrationTables,
    crossUser,
  });
  result.liveFindings = live.findings;
  notes.push(...live.notes);
  notes.push(
    `Supabase live checks done: ${live.tablesChecked} table(s), ${http.sent} request(s), ${live.findings.length} finding(s). Read-only; no writes were made.`,
  );
  return result;
}

/** Orchestrator hook: runs the module with terminal prompts and logging. Never throws. */
export async function supabaseStep(
  projectPath: string,
  opts: { supabase?: SupabaseOptions; yes?: boolean; json?: boolean },
): Promise<{ staticFindings: Finding[]; liveFindings: Finding[] }> {
  const say = (msg: string): void => (opts.json ? logger.stderr(msg) : logger.info(msg));
  try {
    const res = await runSupabase(projectPath, opts.supabase ?? {}, {
      confirm: opts.yes
        ? undefined
        : async (target, mode) => {
            const { ok } = await inquirer.prompt<{ ok: boolean }>([
              {
                type: 'confirm',
                name: 'ok',
                message: `Run read-only Supabase checks against ${target} (ownership: ${mode})? Counts rows visible to the anon key; no data is downloaded, nothing is written.`,
                default: true,
              },
            ]);
            return ok;
          },
    });
    for (const n of res.notes) (res.refused ? logger.warn : say)(redact(n));
    return { staticFindings: res.staticFindings, liveFindings: res.liveFindings };
  } catch (err) {
    logger.warn(`Supabase checks failed: ${redact((err as Error).message)}`);
    return { staticFindings: [], liveFindings: [] };
  }
}
