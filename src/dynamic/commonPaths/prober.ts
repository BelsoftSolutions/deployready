/**
 * Opt-in common-path probe (docs/COMMON-PATH-PROBE-DESIGN.md sections 1.2-1.5). Pure
 * module: nothing calls it yet. Loopback only, GET only, no redirects followed,
 * no credentials sent, at most MAX_PROBE_REQUESTS requests including the control.
 */
import { randomBytes } from 'crypto';
import type { Readable } from 'stream';
import type { AxiosInstance } from 'axios';
import type { CommonPathProbed, CommonPathReport, Finding } from '../../types';
import { logger } from '../../utils/logger';
import { makeFinding } from '../../utils/finding';
import { redact } from '../../utils/redact';
import { assertLoopback, createClient } from '../httpClient';
import { evaluate, fingerprintResponse } from './evidence';
import type { ProbeResponse, ShapeFingerprint, Verdict } from './evidence';
import { PROBE_PATHS } from './signatures';
import type { PathSignature } from './signatures';

export const MAX_PROBE_REQUESTS = 20;
export const BODY_CAP_BYTES = 256 * 1024;
export const REQUEST_TIMEOUT_MS = 5000;
export const DEFAULT_DELAY_MS = 250;
const MAX_CONSECUTIVE_ERRORS = 3;

export type ProbeRequester = (path: string) => Promise<ProbeResponse>;

export class ProbeCapError extends Error {
  constructor(cap: number) {
    super(`common-path probe request cap (${cap}) exceeded`);
    this.name = 'ProbeCapError';
  }
}

/** Counts every request and throws before sending the one past the cap. */
export function capRequester(inner: ProbeRequester, cap = MAX_PROBE_REQUESTS): ProbeRequester {
  let sent = 0;
  return (path) => {
    if (sent >= cap) throw new ProbeCapError(cap);
    sent++;
    return inner(path);
  };
}

function header(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/** One GET; reads at most BODY_CAP_BYTES of the body as a Buffer. */
function httpRequester(client: AxiosInstance): ProbeRequester {
  return async (path) => {
    const res = await client.get(path, {
      responseType: 'stream',
      timeout: REQUEST_TIMEOUT_MS,
      maxRedirects: 0,
      validateStatus: () => true,
    });
    const stream = res.data as Readable;
    const body = await new Promise<Buffer>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let settled = false;
      const settle = (err?: Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        stream.destroy();
        if (err) reject(err);
        else resolve(Buffer.concat(chunks));
      };
      const timer = setTimeout(() => settle(new Error('timeout reading response body')), REQUEST_TIMEOUT_MS);
      stream.on('data', (chunk: Buffer) => {
        const room = BODY_CAP_BYTES - size;
        if (chunk.length > room) {
          chunks.push(chunk.subarray(0, room));
          size = BODY_CAP_BYTES;
          settle();
        } else {
          chunks.push(chunk);
          size += chunk.length;
        }
      });
      stream.on('end', () => settle());
      stream.on('close', () => settle());
      stream.on('error', (e: Error) => settle(e));
    });
    return {
      status: res.status,
      contentType: header(res.headers['content-type']),
      location: header(res.headers['location']),
      body,
    };
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizePath(p: string): string {
  const noQuery = (p.split(/[?#]/)[0] ?? '').toLowerCase();
  return noQuery.length > 1 ? noQuery.replace(/\/+$/, '') : noQuery;
}

function errorReason(e: unknown): string {
  const err = e as { code?: string; message?: string };
  return redact(err.code ?? err.message ?? 'request failed');
}

function safeTarget(baseUrl: string): string {
  const url = assertLoopback(baseUrl);
  url.username = '';
  url.password = '';
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/$/, '');
}

function guessedFinding(path: string, verdict: Verdict, sig: PathSignature): Finding {
  return makeFinding({
    rule: 'common-path-exposure',
    title: `${sig.what} (guessed path, lower confidence)`,
    severity: verdict.severity ?? 'info',
    category: 'security',
    source: 'dynamic',
    endpoint: path,
    owasp: sig.owasp,
    cwe: sig.cwe,
    guessed: true,
    description: redact(
      `${path} was not discovered by the scan; it was requested by the opt-in common-path probe. ` +
        `The response was HTTP 200 and the content proved it: ${sig.proof} (${verdict.evidence ?? 'no values shown'}).`,
    ),
    recommendation: sig.recommendation,
    evidence: verdict.evidence,
  });
}

export interface CommonPathOptions {
  /** Paths already covered by the normal scan (discovered/advertised); never requested here. */
  exclude: string[];
  /** Pause between requests; default 250 ms, 0 in tests. */
  delayMs?: number;
}

export async function runCommonPathProbe(
  baseUrl: string,
  options: CommonPathOptions,
): Promise<{ findings: Finding[]; report: CommonPathReport }> {
  const target = safeTarget(baseUrl);
  const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
  const get = capRequester(httpRequester(createClient(target)));

  const excluded = new Set(options.exclude.map(normalizePath));
  const covered: string[] = [];
  const todo = PROBE_PATHS.filter(({ path }) => {
    if (!excluded.has(normalizePath(path))) return true;
    covered.push(path);
    return false;
  });

  const controlPath = `/__deployready_probe_${randomBytes(6).toString('hex')}`;
  const report: CommonPathReport = {
    target,
    cap: MAX_PROBE_REQUESTS,
    control: { path: controlPath },
    probed: [],
  };
  if (covered.length > 0) report.covered = covered;
  const findings: Finding[] = [];

  let consecutiveErrors = 0;
  let sent = 0;
  const request = async (path: string): Promise<ProbeResponse | Error> => {
    if (sent > 0 && delayMs > 0) await sleep(delayMs);
    sent++;
    try {
      const res = await get(path);
      consecutiveErrors = 0;
      return res;
    } catch (e) {
      if (e instanceof ProbeCapError) throw e;
      consecutiveErrors++;
      return e instanceof Error ? e : new Error(String(e));
    }
  };

  // Negative control: a path that cannot exist. Never reported as a finding.
  let control: ShapeFingerprint | null = null;
  const controlRes = await request(controlPath);
  if (controlRes instanceof Error) {
    logger.debug(`[probe-common] GET ${controlPath} -> error control: ${errorReason(controlRes)}`);
  } else {
    report.control.status = controlRes.status;
    if (controlRes.status >= 200 && controlRes.status < 300) control = fingerprintResponse(controlRes);
    logger.debug(`[probe-common] GET ${controlPath} -> ${controlRes.status} control: negative control for catch-all detection`);
  }

  for (let i = 0; i < todo.length; i++) {
    if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
      report.aborted = `${MAX_CONSECUTIVE_ERRORS} consecutive network errors; ${todo.length - i} path(s) not requested`;
      break;
    }
    const entry = todo[i];
    if (!entry) continue;
    const { path, signature } = entry;
    const res = await request(path);
    let probed: CommonPathProbed;
    if (res instanceof Error) {
      probed = { path, outcome: 'error', reason: errorReason(res) };
    } else {
      const verdict = evaluate(signature, res, control);
      probed = { path, status: res.status, outcome: verdict.outcome, reason: verdict.reason };
      if (verdict.outcome === 'found') {
        findings.push(guessedFinding(path, verdict, signature));
      }
    }
    report.probed.push(probed);
    logger.debug(`[probe-common] GET ${path} -> ${probed.status ?? 'error'} ${probed.outcome}: ${probed.reason}`);
  }
  if (!report.aborted && consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
    report.aborted = `${MAX_CONSECUTIVE_ERRORS} consecutive network errors`;
  }

  return { findings, report };
}
