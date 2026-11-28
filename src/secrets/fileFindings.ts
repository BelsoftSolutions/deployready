/**
 * Secret-only scanning for config / key files (JSON, YAML, TOML, PEM, SSH keys, .http, …)
 * that the source rules never see. Only HIGH-confidence hits are reported here: a
 * secret-named value in a config file is too often a local default to raise on its own
 * (it is still always redacted from every output).
 */
import { makeFinding } from '../utils/finding';
import { redact } from '../utils/redact';
import { detectSecrets } from './detect';
import type { Finding } from '../types';

const LIMIT = 50;

export function secretFileFindings(relPath: string, source: string, out: Finding[]): void {
  if (!source) return;
  const lines = source.split('\n');
  const seen = new Set<number>();
  for (const h of detectSecrets(source)) {
    if (h.confidence !== 'high' || seen.has(h.line)) continue;
    if (seen.size >= LIMIT) break;
    seen.add(h.line);
    out.push(
      makeFinding({
        rule: 'hardcoded-secret',
        title: 'Hardcoded secret / credential in source',
        severity: 'critical',
        category: 'security',
        source: 'static',
        file: relPath,
        line: h.line,
        owasp: 'A02:2025',
        cwe: 'CWE-798',
        description: `A value matching a known secret/credential pattern (${h.id}) was found in ${relPath}.`,
        recommendation:
          'Move the secret to an environment variable or secret manager, rotate the exposed value immediately, and ensure the file is gitignored (or removed from git history if it was committed).',
        evidence: redact((lines[h.line - 1] ?? '').trim()).slice(0, 160),
      }),
    );
  }
}
