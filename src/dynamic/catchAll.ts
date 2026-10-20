/**
 * Catch-all (SPA / wildcard route) detection. A single GET to a path that can
 * never exist tells us whether the app answers 2xx for everything; a probe
 * response identical to that baseline is the catch-all page, not the route.
 */
import { createHash, randomBytes } from 'crypto';
import type { AxiosInstance, AxiosResponse } from 'axios';
import { logger } from '../utils/logger';

const BODY_CAP = 100_000;

export interface Fingerprint {
  status: number;
  length: number;
  hash: string;
}

function bodyText(data: unknown): string {
  if (typeof data === 'string') return data;
  try {
    return JSON.stringify(data) ?? '';
  } catch {
    return '';
  }
}

export function fingerprint(res: Pick<AxiosResponse, 'status' | 'data'>): Fingerprint {
  const text = bodyText(res.data);
  return {
    status: res.status,
    length: text.length,
    hash: createHash('sha256').update(text.slice(0, BODY_CAP)).digest('hex'),
  };
}

/**
 * Negative control: fingerprint of the app's answer to a random path that does
 * not exist, or null if it is not a 2xx catch-all. Callers send it lazily, only
 * when a 2xx on a guarded/sensitive route would otherwise be reported.
 */
export async function probeCatchAll(client: AxiosInstance, reason: string): Promise<Fingerprint | null> {
  const path = `/__deployready_probe_${randomBytes(6).toString('hex')}`;
  logger.debug(
    `[control] GET ${path}: random non-existent path, used only to recognise catch-all pages; sent because ${reason}`,
  );
  try {
    const res = await client.get(path);
    if (res.status < 200 || res.status >= 300) return null;
    return fingerprint(res);
  } catch {
    return null;
  }
}

/** True if a 2xx response is indistinguishable from the catch-all baseline. */
export function isCatchAll(baseline: Fingerprint | null, res: Pick<AxiosResponse, 'status' | 'data'>): boolean {
  if (!baseline || res.status < 200 || res.status >= 300) return false;
  const fp = fingerprint(res);
  return fp.status === baseline.status && (fp.hash === baseline.hash || fp.length === baseline.length);
}
