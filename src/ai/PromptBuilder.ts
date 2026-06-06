/**
 * Builds the AI analysis prompt from the STRUCTURED report only.
 *
 * Hard rule: raw source code is never included. We send a compact, redacted
 * JSON summary of findings + architecture. This is the core privacy/token
 * advantage of EnterpriseReady over "send your whole repo to an LLM" tools.
 */
import { redactObject } from '../utils/redact';
import type { ScanReport } from '../types';

export interface BuiltPrompt {
  system: string;
  user: string;
}

const SYSTEM = `You are EnterpriseReady, an expert application security and QA engineer.
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
      user: `Here is the structured scan report:\n${JSON.stringify(payload, null, 2)}`,
    };
  }

  /** Exactly what will leave the machine, for the consent prompt. */
  static preview(report: ScanReport): string {
    return PromptBuilder.build(report).user;
  }
}
