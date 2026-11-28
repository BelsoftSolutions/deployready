/**
 * Builds the AI analysis prompt from the STRUCTURED report only.
 *
 * Hard rule: raw source code is never included. We send a compact, redacted
 * JSON summary of findings + architecture. This is the core privacy/token
 * advantage of DeployReady over "send your whole repo to an LLM" tools.
 */
import { redact, redactObject } from '../utils/redact';
import type { Finding, ScanReport } from '../types';

export interface BuiltPrompt {
  system: string;
  user: string;
}

const SYSTEM = `You are DeployReady, an expert application security and QA engineer.
You are given a STRUCTURED scan report of a developer's app (no raw source code).
Analyze it and respond with STRICT JSON only, matching this shape:
{
  "summary": "2-4 sentence plain-language assessment, most critical issue first",
  "findings": [
    {
      "rule": "short-kebab-key",
      "title": "...",
      "severity": "critical|warning|info",
      "category": "security|performance|architecture|config",
      "description": "...",
      "recommendation": "concrete fix",
      "file": "optional/path",
      "endpoint": "optional /path",
      "owasp": "optional Axx:2025",
      "cwe": "optional CWE-xxx"
    }
  ]
}
Only add findings that are NOT already in the provided list. Do not invent secrets
or file contents. If nothing to add, return an empty findings array.`;

export class PromptBuilder {
  static build(report: ScanReport): BuiltPrompt {
    // Build a compact, redacted payload. Never include source code.
    const payload = redactObject({
      stack: report.stack,
      score: report.score,
      summary: report.summary,
      architecture: {
        entryPoints: report.graph.entryPoints,
        fileCount: report.graph.fileCount,
        routeCount: report.graph.routes.length,
      },
      findings: report.findings.map((f) => ({
        rule: f.rule,
        title: f.title,
        severity: f.severity,
        category: f.category,
        file: f.file,
        endpoint: f.endpoint,
        owasp: f.owasp,
        cwe: f.cwe,
      })),
    });

    return {
      system: SYSTEM,
      // Second pass over the serialized text: catches secrets in titles/paths that the
      // per-field pass saw only in fragments. Idempotent, so preview() == what is sent.
      user: redact(`Here is the structured scan report:\n${JSON.stringify(payload, null, 2)}`),
    };
  }

  /** Exactly what will leave the machine, for the consent prompt. */
  static preview(report: ScanReport): string {
    return PromptBuilder.build(report).user;
  }

  /**
   * Build a prompt asking the model to rewrite a specific code snippet to fix
   * one finding. The snippet IS code — callers must redact it and obtain consent
   * before sending (this is the only place code leaves the machine, and only for
   * the single snippet around an issue the user chose to fix).
   */
  static buildFixPrompt(finding: Finding, snippet: string, readOnlyContext?: string): BuiltPrompt {
    const system = `You are a senior security engineer fixing ONE issue in a code snippet.
First write a single short sentence explaining the fix.
Then output the COMPLETE corrected snippet inside one fenced code block (triple backticks). Output nothing after the code block.
Rules: change only what is needed to fix the issue; preserve surrounding lines and indentation;
return a full replacement for the snippet marked "to fix"; never invent secrets.
If a READ-ONLY context block is given (the file's imports), use it to understand the code but do NOT repeat or modify it: it is not part of the replaced range.`;
    const context = readOnlyContext
      ? `READ-ONLY context (the file's imports; do not include in your answer):\n\`\`\`\n${readOnlyContext}\n\`\`\`\n\n`
      : '';
    // Callers redact the snippet already; redacting the whole prompt again is the last guard
    // (multi-line private keys, secrets in titles/recommendations from AI findings).
    const user = redact(`Issue: ${finding.title}
Severity: ${finding.severity}${finding.owasp ? ` (${finding.owasp})` : ''}
Recommendation: ${finding.recommendation}

${context}Code snippet to fix (the whole enclosing unit; return it complete):
\`\`\`
${snippet}
\`\`\``);
    return { system, user };
  }
}
