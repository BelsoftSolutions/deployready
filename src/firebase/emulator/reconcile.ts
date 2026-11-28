/**
 * Turns emulator probe results into findings and reconciles them with the static
 * rules findings: confirmed (proof attached), static miss (emulator finding stands
 * alone), or not reproduced (static finding downgraded to a note).
 */
import { makeFinding } from '../../utils/finding';
import { redact } from '../../utils/redact';
import type { Finding, Proof, Severity } from '../../types';
import { OPS, WRITE_OPS, type Op, type ProbeResult, type TargetResult } from './probe';

const OWASP = 'A01:2025';
const CWE = 'CWE-284';
const RANK: Record<Severity, number> = { critical: 3, warning: 2, info: 1 };

export interface Reconciled {
  /** Static findings, possibly with proof attached or downgraded to notes. */
  staticFindings: Finding[];
  /** New findings that only the emulator produced. */
  emulatorFindings: Finding[];
  /** One-line summaries for the CLI/coverage. */
  confirmed: number;
  notReproduced: number;
  staticMisses: number;
}

const opList = (ps: ProbeResult[]): string => [...new Set(ps.map((p) => p.op))].join(', ');

function proofOf(p: ProbeResult, control?: ProbeResult): Proof {
  return {
    request: p.request,
    status: p.status,
    response: p.response,
    ...(control ? { control: `${control.request} -> HTTP ${control.status}` } : {}),
  };
}

export interface Verdict {
  rule: 'firebase-emulator-open-access' | 'firebase-emulator-owner-check-missing';
  severity: Severity;
  hits: ProbeResult[];
}

/** Ops an `allow` statement's method list grants. */
export function opsOf(methods: string[]): Set<Op> {
  const s = new Set<Op>();
  for (const m of methods) {
    if (m === 'read') { s.add('get'); s.add('list'); }
    else if (m === 'write') { s.add('create'); s.add('update'); s.add('delete'); }
    else if ((OPS as string[]).includes(m)) s.add(m as Op);
  }
  return s;
}

/** What the emulator proved for one target: anonymous exposure, then non-owner (signed-in) exposure. */
export function verdictsFor(r: TargetResult): Verdict[] {
  const t = r.target;
  const out: Verdict[] = [];
  const anon = r.probes.filter((p) => p.actor === 'anonymous' && p.allowed);
  if (anon.length) {
    const writes = anon.some((p) => WRITE_OPS.has(p.op));
    out.push({ rule: 'firebase-emulator-open-access', severity: writes || t.recursive || t.userOwned ? 'critical' : 'warning', hits: anon });
  }
  const anonOps = new Set(anon.map((p) => p.op));
  const other = r.probes.filter((p) => p.actor === 'userB' && p.allowed && !anonOps.has(p.op));
  if (other.length) {
    const writes = other.some((p) => WRITE_OPS.has(p.op));
    out.push({ rule: 'firebase-emulator-owner-check-missing', severity: writes ? 'critical' : 'warning', hits: other });
  }
  return out;
}

const staticRule = (f: Finding): boolean => f.rule.startsWith('firebase-rules-');

export function reconcile(staticFindings: Finding[], results: TargetResult[]): Reconciled {
  const out = staticFindings.map((f) => ({ ...f }));
  const emulatorFindings: Finding[] = [];
  let confirmed = 0;
  let notReproduced = 0;
  let staticMisses = 0;

  for (const r of results) {
    if (r.error || r.probes.length === 0) continue;
    const t = r.target;
    const flagged = out.filter((f) => staticRule(f) && !f.note && f.file === t.file && f.line !== undefined && t.lines.includes(f.line));
    const verdicts = verdictsFor(r);
    const control = (op: Op): ProbeResult | undefined => r.probes.find((p) => p.actor === 'userA' && p.op === op);

    for (const v of verdicts) {
      const who = v.rule === 'firebase-emulator-open-access' ? 'an unauthenticated caller' : 'a signed-in user who does not own the data';
      const svc = t.service === 'firestore' ? 'Firestore' : 'Storage';
      const uncovered: ProbeResult[] = [];
      let covered = false;
      for (const h of v.hits) {
        const cover = flagged.filter((f) => {
          const a = t.allows.find((x) => x.line === f.line);
          return a ? opsOf(a.methods).has(h.op) : false;
        });
        if (!cover.length) { uncovered.push(h); continue; }
        covered = true;
        for (const f of cover) {
          if (f.proof) continue;
          f.proof = proofOf(h, control(h.op));
          f.description += ` Confirmed by the Firebase emulator: ${who} was allowed to ${h.op} on ${svc} path ${t.display}.`;
        }
      }
      if (covered) confirmed++;
      if (!uncovered.length) continue;
      const first = uncovered.find((p) => WRITE_OPS.has(p.op)) ?? uncovered[0]!;
      const writes = uncovered.some((p) => WRITE_OPS.has(p.op));
      // Signed-in-only reads on a non-user-owned path (e.g. a shared posts collection) are often intended: note, not finding.
      const soft = v.rule === 'firebase-emulator-owner-check-missing' && !writes && !t.userOwned && !flagged.length;
      const sev: Severity = soft ? 'info' : writes ? 'critical' : v.rule === 'firebase-emulator-open-access' ? v.severity : 'warning';
      if (!flagged.length && !soft) staticMisses++;
      const tail = flagged.length
        ? ' The static analysis flagged this path for other operations; the emulator shows the full impact.'
        : soft
          ? ' Static analysis did not flag it; this is only a note because shared read access for signed-in users is often intended.'
          : ' Static analysis did not flag this rule: the emulator disagrees with it.';
      const line = (t.allows.find((a) => uncovered.some((h) => opsOf(a.methods).has(h.op))) ?? t.allows[0])?.line;
      const ops = opList(uncovered);
      const f = makeFinding({
        rule: v.rule,
        title: v.rule === 'firebase-emulator-open-access'
          ? `Emulator confirmed: anyone can ${ops} at ${t.display}`
          : `Emulator confirmed: any signed-in user can ${ops} other users' data at ${t.display}`,
        severity: sev,
        category: 'security',
        source: 'dynamic',
        file: t.file,
        line,
        owasp: OWASP,
        cwe: CWE,
        description: `In the Firebase emulator running these exact rules, ${who} was allowed to ${ops} on ${svc} path ${t.display}. A control request as the document owner is shown for comparison.${tail}`,
        recommendation: "Require sign-in and compare request.auth.uid to the path variable or to the document's owner field (resource.data.ownerId on read/update/delete, request.resource.data.ownerId on create).",
        evidence: redact(`${first.actor} ${first.op}: HTTP ${first.status}`),
        proof: proofOf(first, control(first.op)),
      });
      emulatorFindings.push(soft ? { ...f, note: true, suggestedSeverity: undefined } : f);
    }
    if (verdicts.length) continue;

    // The emulator denied every anonymous and non-owner probe.
    const conclusive = r.probes.every((p) => p.definitive);
    if (!conclusive) continue;
    for (const f of flagged) {
      const i = out.indexOf(f);
      out[i] = {
        ...f,
        severity: 'info',
        note: true,
        title: `Not reproduced in the emulator: ${f.title}`,
        description: `${f.description} The Firebase emulator, running these rules, denied every anonymous and non-owner get/list/create/update/delete on ${t.display}, so this static finding was not reproduced (for example an expired test-mode rule, or a condition the static reader over-estimated). Verify the rules actually deployed to your project match this file.`,
        suggestedSeverity: f.severity,
      };
      notReproduced++;
    }
  }
  return { staticFindings: out, emulatorFindings, confirmed, notReproduced, staticMisses };
}
