/**
 * Parse a model's raw text into a structured AiAnalysis. Models don't always
 * return clean JSON, so we extract the first balanced JSON object and validate
 * shape defensively — never trust model output structurally.
 */
import { makeFinding } from '../utils/finding';
import type { AiAnalysis, Category, Finding, Severity } from '../types';

const SEVERITIES: Severity[] = ['critical', 'warning', 'info'];
const CATEGORIES: Category[] = ['security', 'performance', 'architecture', 'config'];

export function parseAiResponse(text: string): AiAnalysis {
  const json = extractJson(text);
  if (!json) {
    return { summary: text.trim().slice(0, 2000), findings: [] };
  }

  const summary = typeof json.summary === 'string' ? json.summary : '';
  const rawFindings = Array.isArray(json.findings) ? json.findings : [];
  const findings: Finding[] = [];

  for (const r of rawFindings) {
    if (!r || typeof r !== 'object') continue;
    const o = r as Record<string, unknown>;
    const severity = SEVERITIES.includes(o.severity as Severity) ? (o.severity as Severity) : 'info';
    const category = CATEGORIES.includes(o.category as Category) ? (o.category as Category) : 'security';
    findings.push(
      makeFinding({
        rule: str(o.rule) || 'ai-finding',
        title: str(o.title) || 'AI-identified issue',
        severity,
        category,
        source: 'ai',
        description: str(o.description) || '',
        recommendation: str(o.recommendation) || '',
        file: str(o.file) || undefined,
        endpoint: str(o.endpoint) || undefined,
        owasp: str(o.owasp) || undefined,
        cwe: str(o.cwe) || undefined,
      }),
    );
  }

  return { summary, findings };
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
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
