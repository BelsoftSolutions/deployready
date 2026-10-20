/**
 * Turn a finished CLI run into model text, or a typed ProviderError. Exit code and structured
 * JSON are the primary signals; message patterns are only a secondary hint. Everything that is
 * shown to the user passes through safeSnippet (redacted, no emails, no control characters).
 */
import { redact } from '../../utils/redact';
import { ProviderError } from './errors';
import type { CliProviderSpec } from './providers';
import type { RunCliResult } from './runCli';

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;
// eslint-disable-next-line no-control-regex
const ANSI_RE = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g;

export function safeSnippet(text: string, max = 300): string {
  const clean = redact(text.replace(ANSI_RE, '').replace(CONTROL_RE, ' ').replace(EMAIL_RE, '«email»'))
    .replace(/\s+/g, ' ')
    .trim();
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

const EXPIRED_RE = /expired|invalid[_ ]grant|refresh token|token (has )?been revoked|session (has )?expired/i;
const NOT_LOGGED_IN_RE = /not logged in|please run \/login|run `?(claude|codex)( auth)? login|invalid api key|no credentials|not authenticated|authentication[_ ]error|unauthori[sz]ed|\b401\b|log in|sign in/i;
const USAGE_LIMIT_RE = /usage limit|limit reached|hit your limit|rate[_ ]limit|quota|too many requests|\b429\b|credit balance|try again (at|in)|resets? (at|in)/i;

/** Pick the typed error for an error message (from JSON or stderr) plus an optional numeric HTTP-ish status. */
export function classifyFailure(spec: CliProviderSpec, message: string, status?: number): ProviderError | null {
  const login = spec.loginCommand;
  if (status === 429 || USAGE_LIMIT_RE.test(message)) {
    const reset = /(?:resets?|try again)\s+(?:at|in|on)?\s*([^.|\n]{2,40})/i.exec(message);
    const when = reset?.[1] ? ` It resets ${safeSnippet(reset[1], 40)}.` : '';
    return new ProviderError('usage_limit', `${spec.label}: your plan limit was reached.${when} Nothing was sent anywhere else.`, 'Wait for the limit to reset, or choose another provider.');
  }
  if (status === 401 || status === 403 || EXPIRED_RE.test(message) || NOT_LOGGED_IN_RE.test(message)) {
    if (EXPIRED_RE.test(message)) return new ProviderError('login_expired', `${spec.label}: your login expired.`, `Run \`${login}\` again, then retry.`);
    return new ProviderError('not_logged_in', `${spec.label}: you are not logged in.`, `Run \`${login}\` and retry.`);
  }
  return null;
}

function parseJsonLoose(text: string): unknown {
  const t = text.trim();
  if (!t) return undefined;
  try {
    return JSON.parse(t);
  } catch {
    return undefined;
  }
}

function failureFromRun(spec: CliProviderSpec, res: RunCliResult, hintMessage: string, version?: string): ProviderError {
  const classified = classifyFailure(spec, `${hintMessage}\n${res.stderrTail}`);
  if (classified) return classified;
  const tail = safeSnippet(res.stderrTail || hintMessage, 240);
  const v = version ? ` (CLI version ${safeSnippet(version, 30)})` : '';
  return new ProviderError(
    'nonzero_exit',
    `${spec.label}: the CLI exited with code ${res.exitCode ?? 'none'}${v}${tail ? `: ${tail}` : '.'}`,
  );
}

// ---------------------------------------------------------------- claude

interface ClaudeResult {
  type?: string;
  subtype?: string;
  is_error?: boolean;
  result?: unknown;
  api_error_status?: unknown;
  permission_denials?: unknown;
}

function pickClaudeResult(parsed: unknown): ClaudeResult | undefined {
  if (Array.isArray(parsed)) {
    // Verbose/array form: [{type:'system'}, {type:'assistant'}, ..., {type:'result'}]
    for (const ev of parsed as ClaudeResult[]) {
      const content = (ev as { message?: { content?: unknown } })?.message?.content;
      if (Array.isArray(content) && content.some((b) => (b as { type?: string })?.type === 'tool_use')) {
        throw new ProviderError('tools_used', 'The Claude CLI tried to use a tool although all tools are disabled. The response was discarded.');
      }
    }
    return [...(parsed as ClaudeResult[])].reverse().find((e) => e && e.type === 'result');
  }
  if (parsed && typeof parsed === 'object') return parsed as ClaudeResult;
  return undefined;
}

export function parseClaudeRun(spec: CliProviderSpec, res: RunCliResult, version?: string): string {
  const parsed = pickClaudeResult(parseJsonLoose(res.stdout));
  if (parsed && typeof parsed.result === 'string') {
    const denials = Array.isArray(parsed.permission_denials) ? parsed.permission_denials.length : 0;
    if (denials > 0) {
      throw new ProviderError('tools_used', 'The Claude CLI attempted to use a tool although all tools are disabled. The response was discarded.');
    }
    if (parsed.is_error === true || (res.exitCode !== 0 && res.exitCode !== null)) {
      const status = typeof parsed.api_error_status === 'number' ? parsed.api_error_status : undefined;
      const classified = classifyFailure(spec, parsed.result, status);
      if (classified) throw classified;
      throw new ProviderError('nonzero_exit', `${spec.label}: the CLI reported an error: ${safeSnippet(parsed.result, 240)}`);
    }
    return parsed.result;
  }
  if (res.exitCode !== 0) throw failureFromRun(spec, res, safeSnippet(res.stdout, 200), version);
  throw new ProviderError('bad_output', `${spec.label}: the CLI did not return the expected JSON result.`, version ? `(CLI version ${safeSnippet(version, 30)})` : undefined);
}

// ---------------------------------------------------------------- codex

const CODEX_ALLOWED_ITEMS = new Set(['agent_message', 'reasoning', 'error']);
const CODEX_TOOL_EVENT_RE = /(exec_command|patch_apply|mcp_tool_call|web_search|command_execution|file_change|local_shell|function_call|tool_call)/i;

interface CodexEvent {
  type?: string;
  message?: unknown;
  error?: { message?: unknown } | unknown;
  item?: { type?: string; text?: unknown };
  msg?: { type?: string; message?: unknown };
}

export function parseCodexRun(spec: CliProviderSpec, res: RunCliResult, version?: string): string {
  let finalText: string | undefined;
  let errorText: string | undefined;
  let sawEvent = false;

  for (const line of res.stdout.split(/\r?\n/)) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    let ev: CodexEvent;
    try {
      ev = JSON.parse(t) as CodexEvent;
    } catch {
      continue;
    }
    sawEvent = true;

    const itemType = ev.item?.type;
    const msgType = ev.msg?.type;
    if (itemType && !CODEX_ALLOWED_ITEMS.has(itemType)) {
      throw new ProviderError('tools_used', 'The Codex CLI attempted to use a tool although tools are disabled. The response was discarded.');
    }
    if ((typeof ev.type === 'string' && CODEX_TOOL_EVENT_RE.test(ev.type)) || (msgType && CODEX_TOOL_EVENT_RE.test(msgType))) {
      throw new ProviderError('tools_used', 'The Codex CLI attempted to use a tool although tools are disabled. The response was discarded.');
    }

    if (itemType === 'agent_message' && typeof ev.item?.text === 'string') finalText = ev.item.text;
    else if (msgType === 'agent_message' && typeof ev.msg?.message === 'string') finalText = ev.msg.message;
    else if (ev.type === 'agent_message' && typeof ev.message === 'string') finalText = ev.message;

    if (ev.type === 'error' && typeof ev.message === 'string') errorText = ev.message;
    if (ev.type === 'turn.failed') {
      const m = (ev.error as { message?: unknown } | undefined)?.message;
      if (typeof m === 'string') errorText = m;
    }
  }

  if (errorText && finalText === undefined) {
    const classified = classifyFailure(spec, errorText);
    if (classified) throw classified;
    throw new ProviderError('nonzero_exit', `${spec.label}: the CLI reported an error: ${safeSnippet(errorText, 240)}`);
  }
  if (res.exitCode !== 0) throw failureFromRun(spec, res, errorText ?? '', version);
  if (finalText === undefined || !sawEvent) {
    throw new ProviderError('bad_output', `${spec.label}: the CLI did not return a final message.`, version ? `(CLI version ${safeSnippet(version, 30)})` : undefined);
  }
  return finalText;
}
