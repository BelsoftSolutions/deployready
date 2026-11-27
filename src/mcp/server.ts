/**
 * stdio MCP server: `deployready mcp [path]`. stdout is the protocol, so every log goes to stderr.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { DeployReadyTools } from './tools';
import { supabaseCheck } from './supabase';
import { setQuiet } from '../utils/logger';
import { getVersion } from '../utils/version';

const LOOP =
  'Intended loop: scan -> apply_safe_fixes -> fix the remaining findings yourself (edit the code, using get_finding for context) -> verify each finding id -> score.';

type Handler<A> = (args: A) => Promise<unknown>;

function wrap<A>(fn: Handler<A>): (args: A) => Promise<{ content: { type: 'text'; text: string }[]; isError?: boolean }> {
  return async (args) => {
    try {
      return { content: [{ type: 'text', text: JSON.stringify(await fn(args), null, 2) }] };
    } catch (err) {
      return { content: [{ type: 'text', text: (err as Error).message || 'Unexpected error.' }], isError: true };
    }
  };
}

export function buildMcpServer(tools: DeployReadyTools, projectPath = '.'): McpServer {
  const server = new McpServer({ name: 'deployready', version: getVersion() });
  const pathArg = z.string().optional().describe('Project directory; defaults to the directory the server was started for.');

  server.registerTool(
    'scan',
    {
      description: `Scan the project for security and production-readiness issues (static analysis, no AI, no prompts). Returns findings (id, rule, severity, file, line, evidence, proof) and a score. ${LOOP} Start here.`,
      inputSchema: {
        path: pathArg,
        dynamic: z
          .boolean()
          .optional()
          .describe('Also probe the running localhost app (GET requests only). Requires your app to be running.'),
      },
    },
    wrap(tools.scan.bind(tools)),
  );

  server.registerTool(
    'get_finding',
    {
      description: `Full detail for one finding id from scan: description, fix guidance (recommendation, OWASP, CWE) and, for static findings, the WHOLE file with the finding's line marked ">". Read it, then fix the code with your own edit tools. ${LOOP}`,
      inputSchema: { id: z.string().describe('Finding id from scan.'), path: pathArg },
    },
    wrap(tools.getFinding.bind(tools)),
  );

  server.registerTool(
    'apply_safe_fixes',
    {
      description: `Apply DeployReady's deterministic, backed-up fixes (e.g. add .env to .gitignore, weak hash, disabled TLS verification) and return applied/skipped lists with backup paths. Run it right after scan; whatever is left needs your own edits via get_finding. ${LOOP}`,
      inputSchema: { path: pathArg },
    },
    wrap(tools.applySafeFixes.bind(tools)),
  );

  server.registerTool(
    'verify',
    {
      description: `Re-check one finding after you changed the code. Returns the status exactly as DeployReady reports it (e.g. fixed, still-present, or an unconfirmed status) plus detail. Do not claim a fix until verify says it is fixed. ${LOOP}`,
      inputSchema: { id: z.string().describe('Finding id from scan.'), path: pathArg },
    },
    wrap(tools.verify.bind(tools)),
  );

  server.registerTool(
    'score',
    {
      description: `Re-scan and return the production-readiness score (0-100) and a ready/not-ready verdict (ready = no open critical findings). Call it last to confirm the loop is done. ${LOOP}`,
      inputSchema: { path: pathArg },
    },
    wrap(tools.score.bind(tools)),
  );

  server.registerTool(
    'supabase_check',
    {
      description:
        'Supabase checks. Static (always): service_role keys in client code or public env vars. Live (live: true): read-only proof of what the public anon key can read (row counts, never row data), anon-callable RPC functions, listable storage buckets, auth settings, and optionally a two-user cross-read. Live runs ONLY on a local (loopback) project or one whose ownership is proven by SUPABASE_SERVICE_ROLE_KEY / SUPABASE_ACCESS_TOKEN in the server env; otherwise it is refused. Credentials are read from env vars only. Rotate any leaked service key.',
      inputSchema: {
        path: pathArg,
        live: z.boolean().optional().describe('Run the ownership-gated, read-only live probes (needs SUPABASE_URL + SUPABASE_ANON_KEY, or both in the project files).'),
        crossUser: z
          .boolean()
          .optional()
          .describe('Also test whether test user A can read user B\'s rows (SUPABASE_TEST_USER_A_EMAIL/_PASSWORD and _B_ in env).'),
      },
    },
    wrap((args: { path?: string; live?: boolean; crossUser?: boolean }) => supabaseCheck(projectPath, args)),
  );

  return server;
}

export async function startMcpServer(projectPath = '.'): Promise<void> {
  // stdout is the protocol channel: route every human-facing log (logger, console.log) to stderr.
  setQuiet(true);
  console.log = console.error;
  console.info = console.error;

  const server = buildMcpServer(new DeployReadyTools(projectPath), projectPath);
  await server.connect(new StdioServerTransport());
  console.error(`deployready MCP server ready (stdio), default project: ${projectPath}`);
}
