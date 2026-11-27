/**
 * MCP tool `supabase_check`: the Supabase module (src/supabase) for agents.
 * Static checks always; live checks only with `live: true` AND the same
 * ownership gate as the CLI (loopback URL, or a validated service key / access
 * token). Credentials come from env vars (or, for the public URL + anon key,
 * the project files) only: never from tool arguments, so an agent cannot point
 * it at someone else's project with a key it found. No prompts; nothing printed.
 */
import * as path from 'path';
import { runSupabase, type SupabaseRunDeps } from '../supabase';
import type { Finding } from '../types';

export interface SupabaseCheckArgs {
  path?: string;
  /** Run the live, read-only probes (ownership-gated). */
  live?: boolean;
  /** Also run the two-user cross-read test (SUPABASE_TEST_USER_A/B_* env vars). */
  crossUser?: boolean;
}

export interface SupabaseCheckResult {
  target: string;
  live: boolean;
  refused: boolean;
  findings: Pick<Finding, 'id' | 'rule' | 'severity' | 'title' | 'source' | 'file' | 'line' | 'endpoint' | 'evidence' | 'proof'>[];
  notes: string[];
}

export async function supabaseCheck(
  defaultPath: string,
  args: SupabaseCheckArgs = {},
  deps: Omit<SupabaseRunDeps, 'confirm'> = {},
): Promise<SupabaseCheckResult> {
  const target = path.resolve(defaultPath, args.path ?? '.');
  const live = args.live === true;
  const res = await runSupabase(target, { live, crossUser: args.crossUser === true }, deps);
  const findings = [...res.staticFindings, ...res.liveFindings].map((f) => ({
    id: f.id,
    rule: f.rule,
    severity: f.severity,
    title: f.title,
    source: f.source,
    file: f.file,
    line: f.line,
    endpoint: f.endpoint,
    evidence: f.evidence,
    proof: f.proof,
  }));
  return { target, live, refused: res.refused === true, findings, notes: res.notes };
}
