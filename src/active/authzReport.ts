/**
 * Renders the authorization matrix for the markdown and HTML reports and the
 * terminal. All strings were redacted when the cells were built; the report
 * writers re-redact the whole report anyway (ui/sanitize).
 */
import type { AuthzCell, AuthzMatrix } from './authzTypes';

const ORDER: Record<AuthzCell['verdict'], number> = { violation: 0, inconclusive: 1, untested: 2, 'allowed-as-expected': 3, 'denied-as-expected': 4 };

function sorted(m: AuthzMatrix): AuthzCell[] {
  return [...m.cells].sort((a, b) => ORDER[a.verdict] - ORDER[b.verdict] || a.resource.localeCompare(b.resource) || a.route.localeCompare(b.route) || a.identity.localeCompare(b.identity));
}

export function authzSummaryLine(m: AuthzMatrix): string {
  const s = m.summary;
  return `${s.violation} violation(s) · ${s['denied-as-expected']} denied as expected · ${s['allowed-as-expected']} allowed as expected · ${s.inconclusive} inconclusive · ${s.untested} untested`;
}

const mdCell = (x: string | undefined): string => (x ?? '').replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');

export function authzMarkdown(m: AuthzMatrix | undefined): string[] {
  if (!m) return [];
  const out = ['## Authorization matrix', '', `- **Policy:** \`${m.policySource}\` · safety level \`${m.safetyLevel}\` · ${m.requestsSent} request(s) sent`, `- **Result:** ${authzSummaryLine(m)}`];
  out.push(`- **Identities:** ${m.identities.map((i) => `${i.name} (${i.role}${i.tenant ? `, ${i.tenant}` : ''}${i.available ? '' : `, unavailable: ${i.reason ?? ''}`})`).join(', ')}`);
  if (m.uncoveredRoutes.length) out.push(`- **Not in the policy (not tested):** ${m.uncoveredRoutes.map((r) => `\`${r}\``).join(', ')}`);
  for (const p of m.problems ?? []) out.push(`- Config problem (ignored): ${mdCell(p)}`);
  const violations = m.cells.filter((c) => c.verdict === 'violation');
  if (violations.length) {
    out.push('', '### Violations', '');
    for (const v of violations) out.push(`- **VIOLATION** — ${mdCell(v.statement ?? v.reason)}`);
  }
  out.push('', '| Resource | Route | Identity | Target | Test | Expected | Verdict | Why |', '| --- | --- | --- | --- | --- | --- | --- | --- |');
  for (const c of sorted(m)) {
    out.push(`| ${mdCell(c.resource)} | ${mdCell(c.route)} | ${mdCell(c.identity)} (${mdCell(c.role)}) | ${mdCell(c.target ?? '—')} | ${c.testClass} | ${c.expected} | ${c.verdict === 'violation' ? '**VIOLATION**' : c.verdict} | ${mdCell(c.reason)} |`);
  }
  out.push('');
  return out;
}

function esc(s: string): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export function authzHtml(m: AuthzMatrix | undefined): string {
  if (!m) return '';
  const rows = sorted(m)
    .map(
      (c) =>
        `<tr class="az-${esc(c.verdict)}"><td>${esc(c.resource)}</td><td><code>${esc(c.route)}</code></td><td>${esc(c.identity)} <span class="req">${esc(c.role)}</span></td><td>${esc(c.target ?? '—')}</td><td>${esc(c.testClass)}</td><td>${esc(c.expected)}</td><td><strong>${esc(c.verdict === 'violation' ? 'VIOLATION' : c.verdict)}</strong></td><td>${esc(c.statement ?? c.reason)}</td></tr>`,
    )
    .join('');
  const ids = m.identities.map((i) => `${esc(i.name)} (${esc(i.role)}${i.tenant ? `, ${esc(i.tenant)}` : ''}${i.available ? '' : ', unavailable'})`).join(', ');
  return `<section class="coverage authz"><h2>Authorization matrix</h2>
  <p class="p-meta">Policy <code>${esc(m.policySource)}</code> · safety level ${esc(m.safetyLevel)} · ${m.requestsSent} request(s) · ${esc(authzSummaryLine(m))}</p>
  <p class="p-meta">Identities: ${ids}</p>
  ${m.uncoveredRoutes.length ? `<p class="p-meta">Not in the policy (not tested): ${m.uncoveredRoutes.map((r) => `<code>${esc(r)}</code>`).join(', ')}</p>` : ''}
  <table><thead><tr><th>Resource</th><th>Route</th><th>Identity</th><th>Target</th><th>Test</th><th>Expected</th><th>Verdict</th><th>Why</th></tr></thead><tbody>${rows}</tbody></table>
</section>`;
}

export const AUTHZ_CSS = '.az-violation td{color:#ef4444}.az-inconclusive td,.az-untested td{color:#f59e0b}.az-denied-as-expected td,.az-allowed-as-expected td{color:#9ca3af}';
