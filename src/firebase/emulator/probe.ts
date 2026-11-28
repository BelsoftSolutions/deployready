/**
 * Runs the access matrix against the Firebase emulators over their REST APIs.
 * Every request goes through a Transport that only ever talks to loopback.
 * Seeding uses the emulator's `Bearer owner` admin bypass; actors use unsigned
 * emulator tokens (the emulators accept them; real Firebase never would).
 */
import * as http from 'http';
import { redact } from '../../utils/redact';
import { OTHER_UID, OWNER_UID, type ProbeTarget } from './plan';

export type Op = 'get' | 'list' | 'create' | 'update' | 'delete';
export type Actor = 'anonymous' | 'userA' | 'userB';
export const OPS: Op[] = ['get', 'list', 'create', 'update', 'delete'];
export const ACTORS: Actor[] = ['anonymous', 'userA', 'userB'];
export const WRITE_OPS = new Set<Op>(['create', 'update', 'delete']);

export interface HttpReq { method: string; url: string; headers: Record<string, string>; body?: string }
export interface HttpRes { status: number; body: string }
export type Transport = (r: HttpReq) => Promise<HttpRes>;

const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);

export function assertLoopback(url: string): void {
  const u = new URL(url);
  if (u.protocol !== 'http:' || !LOCAL_HOSTS.has(u.hostname)) throw new Error(`refusing to contact non-loopback host ${u.hostname}`);
}

/** The only network path in this module: plain HTTP to 127.0.0.1 / localhost. */
export function loopbackTransport(timeoutMs = 15_000): Transport {
  return (r) =>
    new Promise((resolve, reject) => {
      try { assertLoopback(r.url); } catch (e) { reject(e); return; }
      const req = http.request(r.url, { method: r.method, headers: { ...r.headers, ...(r.body !== undefined ? { 'content-length': String(Buffer.byteLength(r.body)) } : {}) }, timeout: timeoutMs }, (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (c: Buffer) => { size += c.length; if (size < 256 * 1024) chunks.push(c); });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('timeout', () => req.destroy(new Error('request timed out')));
      req.on('error', reject);
      if (r.body !== undefined) req.write(r.body);
      req.end();
    });
}

const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');

/** Unsigned emulator token (alg "none"). Only the emulators accept it. */
export function emulatorToken(uid: string, projectId: string): string {
  const now = Math.floor(Date.now() / 1000);
  return `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ iss: `https://securetoken.google.com/${projectId}`, aud: projectId, sub: uid, user_id: uid, auth_time: now, iat: now, exp: now + 3600, firebase: { identities: {}, sign_in_provider: 'custom' } })}.`;
}

export interface ProbeEnv {
  transport: Transport;
  projectId: string;
  firestoreBase?: string;
  storageBase?: string;
  bucket: string;
}

export interface ProbeResult {
  op: Op;
  actor: Actor;
  allowed: boolean;
  /** 2xx or 403 only; anything else (400, 404, 5xx, transport error) says nothing about the rules. */
  definitive: boolean;
  status: number;
  /** Redacted, reproducible request (token shown as a placeholder). */
  request: string;
  response: string;
}

export interface TargetResult {
  target: ProbeTarget;
  probes: ProbeResult[];
  /** Set when the admin seed failed: the target could not be tested. */
  error?: string;
}

const who = (a: Actor): string => (a === 'anonymous' ? '' : a === 'userA' ? OWNER_UID : OTHER_UID);

function render(r: HttpReq, actor: Actor): string {
  const h = Object.keys(r.headers).filter((k) => k.toLowerCase() !== 'authorization').map((k) => ` -H '${k}: ${r.headers[k]}'`).join('');
  const auth = actor === 'anonymous' ? '' : ` -H 'Authorization: Bearer <unsigned emulator token for uid "${who(actor)}">'`;
  return redact(`curl -X ${r.method} '${r.url}'${auth}${h}${r.body !== undefined ? ` -d '${r.body.slice(0, 300)}'` : ''}`);
}

interface Adapter {
  seed(): HttpReq;
  unseed(): HttpReq;
  req(op: Op): HttpReq;
  needsSeed(op: Op): boolean;
}

const JSON_H = { 'content-type': 'application/json' };

function fsFields(t: ProbeTarget, marker: string): string {
  const fields: Record<string, { stringValue: string }> = { dr_probe: { stringValue: marker } };
  for (const f of t.ownerFields) fields[f] = { stringValue: OWNER_UID };
  return JSON.stringify({ fields });
}

function firestoreAdapter(env: ProbeEnv, t: ProbeTarget): Adapter {
  const root = `${env.firestoreBase}/v1/projects/${env.projectId}/databases/(default)/documents`;
  const doc = `${root}/${t.docPath}`;
  return {
    seed: () => ({ method: 'PATCH', url: doc, headers: JSON_H, body: fsFields(t, 'seed') }),
    unseed: () => ({ method: 'DELETE', url: doc, headers: {} }),
    needsSeed: (op) => op !== 'create',
    req: (op) => {
      switch (op) {
        case 'get': return { method: 'GET', url: doc, headers: {} };
        case 'list': return { method: 'GET', url: `${root}/${t.collectionPath}?pageSize=1`, headers: {} };
        case 'create': return { method: 'PATCH', url: `${doc}?currentDocument.exists=false`, headers: JSON_H, body: fsFields(t, 'create') };
        case 'update': return { method: 'PATCH', url: `${doc}?updateMask.fieldPaths=dr_probe&currentDocument.exists=true`, headers: JSON_H, body: JSON.stringify({ fields: { dr_probe: { stringValue: 'update' } } }) };
        case 'delete': return { method: 'DELETE', url: doc, headers: {} };
      }
    },
  };
}

function storageAdapter(env: ProbeEnv, t: ProbeTarget): Adapter {
  const base = `${env.storageBase}/v0/b/${env.bucket}/o`;
  const obj = `${base}/${encodeURIComponent(t.docPath)}`;
  const upload = (): HttpReq => ({ method: 'POST', url: `${base}?name=${encodeURIComponent(t.docPath)}&uploadType=media`, headers: { 'content-type': 'text/plain' }, body: 'deployready-probe' });
  return {
    seed: upload,
    unseed: () => ({ method: 'DELETE', url: obj, headers: {} }),
    needsSeed: (op) => op !== 'create',
    req: (op) => {
      switch (op) {
        case 'get': return { method: 'GET', url: obj, headers: {} };
        case 'list': return { method: 'GET', url: `${base}?prefix=${encodeURIComponent(t.collectionPath)}&maxResults=1`, headers: {} };
        case 'create':
        case 'update': return upload();
        case 'delete': return { method: 'DELETE', url: obj, headers: {} };
      }
    },
  };
}

const ADMIN = { Authorization: 'Bearer owner' };

/** Run the 5 operations x 3 actors matrix for one target. Never throws. */
export async function runTarget(env: ProbeEnv, t: ProbeTarget): Promise<TargetResult> {
  const probes: ProbeResult[] = [];
  if ((t.service === 'firestore' && !env.firestoreBase) || (t.service === 'storage' && !env.storageBase)) {
    return { target: t, probes, error: `${t.service} emulator not running` };
  }
  const ad = t.service === 'firestore' ? firestoreAdapter(env, t) : storageAdapter(env, t);
  const admin = async (r: HttpReq): Promise<HttpRes> => env.transport({ ...r, headers: { ...r.headers, ...ADMIN } });
  try {
    for (const op of OPS) {
      for (const actor of ACTORS) {
        // Reset state as admin so each probe starts from a known document/object.
        const prep = ad.needsSeed(op) ? await admin(ad.seed()) : await admin(ad.unseed());
        if (ad.needsSeed(op) ? prep.status >= 300 : prep.status >= 500) {
          return { target: t, probes, error: `admin seed failed (HTTP ${prep.status}): ${redact(prep.body).slice(0, 200)}` };
        }
        const r = ad.req(op);
        const headers = { ...r.headers, ...(actor === 'anonymous' ? {} : { Authorization: `Bearer ${emulatorToken(who(actor), env.projectId)}` }) };
        let res: HttpRes;
        try {
          res = await env.transport({ ...r, headers });
        } catch (e) {
          probes.push({ op, actor, allowed: false, definitive: false, status: 0, request: render(r, actor), response: redact((e as Error).message) });
          continue;
        }
        const allowed = res.status >= 200 && res.status < 300;
        probes.push({ op, actor, allowed, definitive: allowed || res.status === 403, status: res.status, request: render(r, actor), response: redact(res.body.replace(/\s+/g, ' ').trim()).slice(0, 300) });
      }
    }
    await admin(ad.unseed()).catch(() => undefined);
  } catch (e) {
    return { target: t, probes, error: redact((e as Error).message) };
  }
  return { target: t, probes };
}

export async function runPlan(env: ProbeEnv, targets: ProbeTarget[]): Promise<TargetResult[]> {
  const out: TargetResult[] = [];
  for (const t of targets) out.push(await runTarget(env, t));
  return out;
}
