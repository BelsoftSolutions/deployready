/**
 * A short, paste-ready instruction a developer can give their own coding agent to fix one finding.
 *
 * Pure and offline: it is built only from the finding's metadata (title, location, CWE/OWASP,
 * recommendation). It never includes raw source code or evidence/proof, and the result is passed
 * through redact() as a last guard.
 */
import { redact } from '../utils/redact';
import type { Finding } from '../types';

export interface FixPromptOptions {
  /**
   * Include the MCP `verify` hint (the id is only meaningful when the agent talks to the
   * DeployReady MCP server). Default true.
   */
  mcp?: boolean;
}

export function buildFixPrompt(finding: Finding, opts: FixPromptOptions = {}): string {
  const where = finding.endpoint ?? (finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : '');
  const refs = [finding.cwe, finding.owasp].filter(Boolean).join(', ');
  const sev = finding.severity;

  const lines = [
    `Fix one ${sev} security issue that DeployReady found in this project.`,
    '',
    where ? `Where: ${where}` : '',
    `Issue: ${oneLine(finding.title)}${refs ? ` (${refs})` : ''}`,
    `What to change: ${oneLine(finding.recommendation)}`,
    '',
    'Keep the fix minimal: change only what this issue needs, do not change behaviour or refactor unrelated code, and never put real secrets in code or in your reply (use environment variables).',
    `To confirm: re-run \`npx deployready@latest analyze\` and check this issue is gone${
      opts.mcp === false ? '' : `, or call the DeployReady MCP \`verify\` tool with id "${finding.id}"`
    }.`,
  ];
  return redact(lines.filter((l, i) => l !== '' || lines[i - 1] !== '').join('\n').replace(/\n{3,}/g, '\n\n'));
}

function oneLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}
