/**
 * Parse a model's raw text into a structured AiAnalysis. Models don't always
 * return clean JSON, so we extract the first balanced JSON object and validate
 * shape defensively — never trust model output structurally.
 */
import { makeFinding } from '../utils/finding';
import { sanitizeLine, sanitizeText } from '../utils/sanitize';
import type { AiAnalysis, Category, Finding, Severity } from '../types';

const SEVERITIES: Severity[] = ['critical', 'warning', 'info'];
const CATEGORIES: Category[] = ['security', 'performance', 'architecture', 'config'];

/** A model reply is untrusted: bound how much of it can reach the report. */
const MAX_FINDINGS = 50;
const MAX_SUMMARY = 4000;
const MAX_FIELD = 600;
const MAX_LONG_FIELD = 2000;

export function parseAiResponse(text: string): AiAnalysis {
  const json = extractJson(text);
  if (!json) {
    return { summary: sanitizeText(text).trim().slice(0, 2000), findings: [] };
  }

  const summary = typeof json.summary === 'string' ? sanitizeText(json.summary).slice(0, MAX_SUMMARY) : '';
  const rawFindings = Array.isArray(json.findings) ? json.findings : [];
  const findings: Finding[] = [];

  for (const r of rawFindings.slice(0, MAX_FINDINGS)) {
    if (!r || typeof r !== 'object') continue;
    const o = r as Record<string, unknown>;
    const severity = SEVERITIES.includes(o.severity as Severity) ? (o.severity as Severity) : 'info';
    const category = CATEGORIES.includes(o.category as Category) ? (o.category as Category) : 'security';
    findings.push(
      makeFinding({
        rule: line(o.rule, 80) || 'ai-finding',
        title: line(o.title, MAX_FIELD) || 'AI-identified issue',
        severity,
        category,
        source: 'ai',
        unverified: true,
        description: longText(o.description, MAX_LONG_FIELD),
        recommendation: longText(o.recommendation, MAX_LONG_FIELD),
        file: line(o.file, 300) || undefined,
        endpoint: line(o.endpoint, 300) || undefined,
        owasp: line(o.owasp, 40) || undefined,
        cwe: line(o.cwe, 40) || undefined,
      }),
    );
  }

  return { summary, findings };
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function line(v: unknown, max: number): string {
  return sanitizeLine(str(v)).trim().slice(0, max);
}

function longText(v: unknown, max: number): string {
  return sanitizeText(str(v)).slice(0, max);
}

/** Extract the first balanced {...} block and JSON.parse it. */
function extractJson(text: string): Record<string, unknown> | null {
  const start = text.indexOf('{');
  if (start === -1) return null;
  let depth = 0;
  for (let i = start; i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') {
      depth--;
      if (depth === 0) {
        try {
          return JSON.parse(text.slice(start, i + 1)) as Record<string, unknown>;
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}
