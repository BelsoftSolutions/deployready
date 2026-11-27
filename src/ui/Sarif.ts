/**
 * SARIF 2.1.0 export for GitHub code scanning (`analyze --sarif <file>`).
 *
 * GitHub only accepts results that have a physical file location, so findings
 * without a file (live/dynamic endpoint findings) are skipped and listed as a
 * tool-execution notification instead. Unverified AI suggestions and
 * informational notes are never emitted. Evidence is already redacted upstream;
 * it is only ever appended to the message text.
 */
import { fingerprint } from '../core/CiGate';
import { isNonScored } from '../analysis/ScoreCalculator';
import type { Finding, ScanReport, Severity } from '../types';

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const INFO_URI = 'https://github.com/BelsoftSolutions/deployready';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', warning: 'warning', info: 'note' };
/** GitHub's security-severity buckets: >=9 critical, 7-8.9 high, 4-6.9 medium, 0.1-3.9 low. */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.0', warning: '5.5', info: '3.0' };
const RANK: Record<Severity, number> = { critical: 3, warning: 2, info: 1 };

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<Record<string, unknown>>;
}

/** Normalise a project-relative path to a forward-slash, repo-root-relative URI. */
function toUri(file: string): string {
  return file.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
}

function ruleTags(f: Finding): string[] {
  const tags = ['security', f.category];
  if (f.cwe) tags.push(`external/cwe/${f.cwe.toLowerCase()}`);
  if (f.owasp) tags.push(`external/owasp/${f.owasp}`);
  return Array.from(new Set(tags));
}

function messageText(f: Finding): string {
  const base = `${f.title}: ${f.description}`;
  return f.evidence ? `${base} Evidence: ${f.evidence}` : base;
}

export function toSarif(report: ScanReport, version: string): SarifLog {
  const included: Finding[] = [];
  const skipped: Finding[] = [];
  for (const f of report.findings) {
    if (isNonScored(f)) continue;
    (f.file ? included : skipped).push(f);
  }

  const rules = new Map<string, Finding[]>();
  for (const f of included) rules.set(f.rule, [...(rules.get(f.rule) ?? []), f]);
  const ruleIds = Array.from(rules.keys()).sort();

  const ruleDefs = ruleIds.map((id) => {
    const fs = rules.get(id) as Finding[];
    const top = fs.reduce((a, b) => (RANK[b.severity] > RANK[a.severity] ? b : a));
    return {
      id,
      name: id,
      shortDescription: { text: top.title },
      fullDescription: { text: top.description },
      help: { text: top.recommendation, markdown: top.recommendation },
      defaultConfiguration: { level: LEVEL[top.severity] },
      properties: {
        tags: ruleTags(top),
        'security-severity': SECURITY_SEVERITY[top.severity],
        precision: 'medium',
      },
    };
  });

  const results = included.map((f) => ({
    ruleId: f.rule,
    ruleIndex: ruleIds.indexOf(f.rule),
    level: LEVEL[f.severity],
    message: { text: messageText(f) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toUri(f.file as string), uriBaseId: '%SRCROOT%' },
          region: { startLine: f.line && f.line > 0 ? f.line : 1 },
        },
      },
    ],
    partialFingerprints: { 'deployready/v1': fingerprint(f) },
    properties: { 'security-severity': SECURITY_SEVERITY[f.severity], source: f.source },
  }));

  const notifications = skipped.map((f) => ({
    level: 'note',
    message: {
      text: `Not in SARIF (no source file): [${f.severity}] ${f.rule}${f.endpoint ? ` at ${f.endpoint}` : ''}. See the JSON or HTML report.`,
    },
  }));

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'DeployReady', version, informationUri: INFO_URI, rules: ruleDefs } },
        originalUriBaseIds: { '%SRCROOT%': { uri: 'file:///' } },
        invocations: [{ executionSuccessful: true, toolExecutionNotifications: notifications }],
        results,
      },
    ],
  };
}
