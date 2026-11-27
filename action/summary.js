#!/usr/bin/env node
'use strict';
/**
 * Builds the markdown summary / sticky PR comment for the DeployReady GitHub Action
 * from the `analyze --json` report. Dependency-free (runs on any Node >= 18).
 *
 * CLI: node summary.js <report.json> [--exit-code N] [--fail-on LEVEL] [--run-url URL] [--out FILE]
 */
const fs = require('fs');

const MARKER = '<!-- deployready -->';
const RANK = { critical: 0, warning: 1, info: 2 };
const TOP_N = 10;

/** Escape text for use inside a markdown table cell / inline code-free line. */
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/[\r\n]+/g, ' ')
    .replace(/\|/g, '\\|')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function where(f) {
  if (f.file) return f.line ? `${f.file}:${f.line}` : f.file;
  return f.endpoint || '-';
}

function buildSummary(report, opts) {
  const o = opts || {};
  const lines = [MARKER, '## DeployReady scan', ''];
  if (!report || typeof report !== 'object' || !report.summary) {
    lines.push(`DeployReady did not produce a report (exit code ${o.exitCode == null ? 'unknown' : o.exitCode}). Check the workflow logs.`);
    if (o.runUrl) lines.push('', `[Workflow run](${o.runUrl})`);
    return lines.join('\n') + '\n';
  }
  const s = report.summary;
  const failed = o.exitCode != null && Number(o.exitCode) !== 0;
  lines.push(
    `**Score: ${report.score}/100** - ${failed ? `gate failed (fail-on: ${o.failOn || report.failOn || 'critical'})` : 'gate passed'}`,
    '',
    '| Critical | Warning | Info |',
    '| ---: | ---: | ---: |',
    `| ${s.critical} | ${s.warning} | ${s.info} |`,
    '',
  );
  const b = report.baseline;
  if (b && typeof b === 'object') {
    const n = (x) => (Array.isArray(x) ? x.length : 0);
    lines.push(
      `Baseline: ${n(b.new)} new, ${n(b.escalated)} escalated, ${n(b.reopened)} reopened, ${n(b.expired)} expired, ${n(b.stale)} stale (${Number(b.known) || 0} known, suppressed).`,
      '',
    );
  }
  const findings = (Array.isArray(report.findings) ? report.findings : [])
    .filter((f) => !f.unverified && !f.note)
    .slice()
    .sort((a, b) => (RANK[a.severity] ?? 3) - (RANK[b.severity] ?? 3));
  if (findings.length === 0) {
    lines.push('No findings. Nice work.');
  } else {
    lines.push(`### Top ${Math.min(TOP_N, findings.length)} of ${findings.length} findings`, '', '| Severity | Finding | Location |', '| --- | --- | --- |');
    for (const f of findings.slice(0, TOP_N)) {
      lines.push(`| ${esc(f.severity)} | ${esc(f.title)} (\`${esc(f.rule)}\`) | ${esc(where(f))} |`);
    }
    if (findings.length > TOP_N) lines.push('', `...and ${findings.length - TOP_N} more in the full report.`);
  }
  lines.push('');
  if (o.runUrl) lines.push(`[Full report (artifact: deployready-report)](${o.runUrl})`);
  return lines.join('\n') + '\n';
}

function main(argv) {
  const args = {};
  for (let i = 3; i < argv.length; i += 2) args[argv[i].replace(/^--/, '')] = argv[i + 1];
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(argv[2], 'utf8'));
  } catch {
    /* missing or invalid report: summary says so */
  }
  const md = buildSummary(report, { exitCode: args['exit-code'], failOn: args['fail-on'], runUrl: args['run-url'] });
  if (args.out) fs.writeFileSync(args.out, md);
  else process.stdout.write(md);
}

module.exports = { buildSummary, MARKER };
if (require.main === module) main(process.argv);
