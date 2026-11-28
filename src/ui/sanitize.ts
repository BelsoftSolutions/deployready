/**
 * Last-guard output sanitization for every report renderer (terminal, markdown, HTML,
 * SARIF, JSON). Findings are redacted when created, but titles/descriptions can carry
 * AI-written or response-derived text, so each exit re-redacts the whole report.
 * redact() is idempotent, so applying it twice is harmless.
 */
import { redact, redactDeep } from '../utils/redact';
import type { Finding, Proof, ScanReport } from '../types';

export function sanitizeReport(report: ScanReport): ScanReport {
  return redactDeep(report);
}

export function sanitizeFinding(f: Finding): Finding {
  return redactDeep(f);
}

export function sanitizeProof(p: Proof): Proof {
  return redactDeep(p);
}

/** JSON report body for stdout (`analyze --json`). */
export function renderJson(body: unknown): string {
  return JSON.stringify(redactDeep(body), null, 2) + '\n';
}

export { redact };
