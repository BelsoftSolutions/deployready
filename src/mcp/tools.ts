/**
 * MCP tool handlers. Plain async functions so tests (and the stdio server) call the same code.
 * Everything here is non-interactive: no prompts, no AI analysis. Nothing may write to stdout.
 */
import * as path from 'path';
import { Orchestrator } from '../core/Orchestrator';
import { Verifier } from '../core/Verifier';
import type { VerifyContext } from '../core/Verifier';
import { FileEditor } from '../agent/FileEditor';
import { FixManager } from '../agent/FixManager';
import { isNonScored } from '../analysis/ScoreCalculator';
import { applySafeFixes } from './fixes';
import type { SafeFixResult } from './fixes';
import { assess } from './readiness';
import type { Readiness } from './readiness';
import type { Finding, ScanReport } from '../types';

const EVIDENCE_MAX = 200;
const FILE_MAX_BYTES = 256 * 1024;

interface CachedScan {
  target: string;
  dynamic: boolean;
  report: ScanReport;
  /** Every finding seen for this path this session, so ids stay resolvable after a re-scan. */
  known: Map<string, Finding>;
}

export interface FindingSummary {
  id: string;
  rule: string;
  severity: string;
  title: string;
  source: string;
  file?: string;
  line?: number;
  endpoint?: string;
  evidence?: string;
  proof?: Finding['proof'];
  note?: boolean;
}

export interface ScanResult extends Readiness {
  target: string;
  dynamic: boolean;
  findings: FindingSummary[];
  hint: string;
}

export class DeployReadyTools {
  private readonly cache = new Map<string, CachedScan>();

  /** @param defaultPath project used when a tool call omits `path` (the `mcp [path]` argument). */
  constructor(private readonly defaultPath: string = '.') {}

  private resolve(p?: string): string {
    return path.resolve(this.defaultPath, p ?? '.');
  }

  private async runScan(target: string, dynamic: boolean): Promise<CachedScan> {
    const report = await Orchestrator.analyze(target, { yes: true, json: true, noAi: true, noDynamic: !dynamic });
    const known = this.cache.get(target)?.known ?? new Map<string, Finding>();
    for (const f of report.findings) known.set(f.id, f);
    const entry: CachedScan = { target, dynamic, report, known };
    this.cache.set(target, entry);
    return entry;
  }

  async scan(args: { path?: string; dynamic?: boolean } = {}): Promise<ScanResult> {
    const entry = await this.runScan(this.resolve(args.path), args.dynamic === true);
    return {
      target: entry.target,
      dynamic: entry.dynamic,
      ...assess(entry.report.findings),
      findings: entry.report.findings.map(summarize),
      hint: 'Next: apply_safe_fixes, then get_finding for each remaining finding, fix it with your own edits, verify(id), and finish with score.',
    };
  }

  private find(id: string, p?: string): { entry: CachedScan; finding: Finding } {
    const candidates = p ? [this.cache.get(this.resolve(p))] : [...this.cache.values()];
    if (candidates.every((c) => !c)) throw new Error('No scan yet for this path. Call scan first.');
    for (const entry of candidates) {
      const finding = entry?.known.get(id);
      if (entry && finding) return { entry, finding };
    }
    throw new Error(`Unknown finding id "${id}". Call scan to list current ids.`);
  }

  async getFinding(args: { id: string; path?: string }): Promise<Record<string, unknown>> {
    const { entry, finding } = this.find(args.id, args.path);
    const out: Record<string, unknown> = {
      ...summarize(finding),
      category: finding.category,
      description: finding.description,
      fix: {
        recommendation: finding.recommendation,
        owasp: finding.owasp,
        cwe: finding.cwe,
        deterministicFixAvailable: FixManager.autoFixable(finding),
      },
    };
    if (finding.source === 'static' && finding.file) {
      try {
        const content = await new FileEditor(entry.target).read(finding.file);
        out.file_content = renderFile(content, finding.line);
        out.file_truncated = Buffer.byteLength(content) > FILE_MAX_BYTES;
      } catch (err) {
        out.file_error = (err as Error).message;
      }
    }
    return out;
  }

  async applySafeFixes(args: { path?: string } = {}): Promise<SafeFixResult & Readiness & { note: string }> {
    const target = this.resolve(args.path);
    const entry = this.cache.get(target) ?? (await this.runScan(target, false));
    const result = await applySafeFixes(target, entry.report.findings);
    // The files changed: refresh so score and ids reflect disk.
    const fresh = result.applied.length > 0 ? await this.runScan(target, entry.dynamic) : entry;
    return {
      ...result,
      ...assess(fresh.report.findings),
      note:
        result.applied.length === 0
          ? 'No deterministic fix applied. Use get_finding and edit the code yourself.'
          : 'Applied fixes are backed up (see backup paths). Remaining findings need your own edits; use get_finding.',
    };
  }

  async verify(args: { id: string; path?: string }): Promise<{ id: string; status: string; detail?: string }> {
    const { entry, finding } = this.find(args.id, args.path);
    const ctx: VerifyContext = { target: entry.target };
    if (entry.report.dynamic?.baseUrl) {
      ctx.dynamic = { baseUrl: entry.report.dynamic.baseUrl, routes: entry.report.graph.routes };
    }
    const res = await Verifier.verify(finding, ctx);
    return { id: finding.id, status: res.status, detail: res.detail };
  }

  async score(args: { path?: string } = {}): Promise<Readiness & { target: string; openCritical: FindingSummary[] }> {
    const target = this.resolve(args.path);
    const entry = await this.runScan(target, this.cache.get(target)?.dynamic ?? false);
    return {
      target,
      ...assess(entry.report.findings),
      openCritical: entry.report.findings.filter((f) => !isNonScored(f) && f.severity === 'critical').map(summarize),
    };
  }
}

function summarize(f: Finding): FindingSummary {
  const ev = f.evidence && f.evidence.length > EVIDENCE_MAX ? f.evidence.slice(0, EVIDENCE_MAX) + '…' : f.evidence;
  return {
    id: f.id,
    rule: f.rule,
    severity: f.severity,
    title: f.title,
    source: f.source,
    file: f.file,
    line: f.line,
    endpoint: f.endpoint,
    evidence: ev,
    proof: f.proof,
    note: f.note ? true : undefined,
  };
}

/** Whole file, numbered, with the finding's line marked `>`. */
function renderFile(content: string, line?: number): string {
  const text = content.length > FILE_MAX_BYTES ? content.slice(0, FILE_MAX_BYTES) : content;
  const lines = text.split(/\r?\n/);
  const width = String(lines.length).length;
  return lines.map((l, i) => `${i + 1 === line ? '>' : ' '} ${String(i + 1).padStart(width)} | ${l}`).join('\n');
}
