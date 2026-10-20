/**
 * Routes the running app advertises itself, read from responses the scan already
 * fetched from discovered/spec routes: same-origin links, Link headers, and
 * robots.txt / sitemap.xml / OpenAPI documents that are themselves evidence.
 * Nothing is guessed: robots.txt and sitemap.xml are never requested unless a
 * project file, a discovered route or a fetched response points at them.
 * Depth 1, GET only, at most MAX_ADVERTISED new paths per scan.
 */
import * as fs from 'fs';
import * as path from 'path';
import type { AxiosInstance } from 'axios';
import { routesFromSpecDocument } from '../parser/openapi';
import { logger } from '../utils/logger';
import { adminEvidence } from './adminEvidence';
import { EndpointMapper, type ProbeTarget } from './EndpointMapper';
import type { Resp } from './httpClient';

export const MAX_ADVERTISED = 25;

const STATIC_DIRS = ['', 'public', 'static', 'www', 'dist'];
const ASSET_EXT = /\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|pdf|zip)$/i;
const STATE_CHANGING = /(^|[^a-z0-9])(logout|signout|sign-out|log-out|delete|remove|destroy|unsubscribe|revoke|reset|cancel)([^a-z0-9]|$)/;
const PARSE_CAP = 512 * 1024;
const MAX_SITEMAP_ENTRIES = 1000;
const MAX_SPEC_BYTES = 2 * 1024 * 1024;
const LINK_RELS: Record<string, DocKind> = { sitemap: 'sitemap', 'service-desc': 'spec', describedby: 'spec' };

type DocKind = 'sitemap' | 'spec';

interface Candidate {
  path: string;
  why: string[];
  guarded: boolean;
  kind?: DocKind;
}

export interface StaticEvidence {
  robots?: string;
  sitemap?: string;
}

/** robots.txt / sitemap.xml files in the project's static directories or root (relative paths). */
export function staticEvidence(projectPath: string): StaticEvidence {
  const found: StaticEvidence = {};
  for (const [key, name] of [['robots', 'robots.txt'], ['sitemap', 'sitemap.xml']] as const) {
    for (const dir of STATIC_DIRS) {
      const file = path.join(projectPath, dir, name);
      try {
        if (fs.statSync(file).isFile()) {
          found[key] = dir ? `${dir}/${name}` : name;
          break;
        }
      } catch {
        // not there
      }
    }
  }
  return found;
}

/** Reason an advertised path must not be requested, or null. */
export function advertisedSkipReason(p: string): string | null {
  const unusable = EndpointMapper.unrequestable(p);
  if (unusable) return unusable;
  const last = p.split('/').pop() ?? '';
  if (ASSET_EXT.test(last)) return 'static asset';
  const words = p.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase();
  if (STATE_CHANGING.test(words)) return 'a GET link with a state-changing name';
  return null;
}

/** The URL path of `href` seen on the page at `pagePath`, or null if it is not a plain same-origin path. */
export function toLocalPath(href: string, pagePath: string, baseUrl: string): string | null {
  const raw = href.trim();
  if (!raw || raw.startsWith('#')) return null;
  let base: URL;
  let u: URL;
  try {
    base = new URL(baseUrl);
    u = new URL(raw, new URL(pagePath, base));
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (u.origin !== base.origin) return null;
  if (u.search) return null;
  return u.pathname || '/';
}

/** href values of `<a>` and `<link>` tags. `<form action>` is deliberately not read. */
export function extractHrefs(html: string): string[] {
  const out: string[] = [];
  const tagRe = /<(a|link)\b([^>]*)>/gi;
  for (let m = tagRe.exec(html); m; m = tagRe.exec(html)) {
    const attr = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i.exec(m[2] ?? '');
    const value = attr?.[1] ?? attr?.[2] ?? attr?.[3];
    if (value) out.push(decodeEntities(value));
  }
  return out;
}

/** `Link:` header entries whose rel is sitemap, service-desc or describedby. */
export function linkHeaderTargets(header: unknown): { url: string; rel: string }[] {
  const value = Array.isArray(header) ? header.join(', ') : typeof header === 'string' ? header : '';
  const out: { url: string; rel: string }[] = [];
  const re = /<([^>]*)>([^<]*)/g;
  for (let m = re.exec(value); m; m = re.exec(value)) {
    const relParam = /;\s*rel\s*=\s*(?:"([^"]*)"|([^\s;,]+))/i.exec(m[2] ?? '');
    const rels = (relParam?.[1] ?? relParam?.[2] ?? '').toLowerCase().split(/\s+/);
    const rel = rels.find((r) => r in LINK_RELS);
    if (rel && m[1]) out.push({ url: m[1], rel });
  }
  return out;
}

export function robotsSitemaps(text: string): string[] {
  return [...text.matchAll(/^\s*sitemap\s*:\s*(\S+)/gim)].map((m) => m[1]!);
}

export function sitemapLocs(xml: string): { locs: string[]; index: boolean } {
  const locs = [...xml.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)].slice(0, MAX_SITEMAP_ENTRIES).map((m) => decodeEntities(m[1]!));
  return { locs, index: /<sitemapindex\b/i.test(xml) };
}

function decodeEntities(s: string): string {
  return s.replace(/&amp;/gi, '&').replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'");
}

const keyOf = (p: string): string => p.replace(/\/+$/, '') || '/';

function textOf(res: Resp): string | null {
  return typeof res.data === 'string' ? res.data.slice(0, PARSE_CAP) : null;
}

/** An OpenAPI/Swagger document in the body (JSON object, or JSON text), else null. */
function specDocument(res: Resp): unknown {
  let doc: unknown = res.data;
  if (typeof doc === 'string') {
    if (doc.length > MAX_SPEC_BYTES || !doc.trimStart().startsWith('{')) return null;
    try {
      doc = JSON.parse(doc);
    } catch {
      return null;
    }
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return null;
  const o = doc as Record<string, unknown>;
  const paths = o.paths;
  if (!('openapi' in o || 'swagger' in o) || typeof paths !== 'object' || paths === null || Array.isArray(paths)) return null;
  return doc;
}

export interface Advertised {
  /** New targets, in request order, each already fetched once. */
  targets: ProbeTarget[];
  /** The response fetched for every initial and advertised path (null = network error). */
  responses: Map<string, Resp | null>;
}

/**
 * Fetch each initial target once, read what those responses advertise, fetch
 * the advertised paths once (documents among them are read, pages are not
 * crawled), and return the extra targets. The fetched responses are handed on
 * so the checks do not request the same path an extra time.
 */
export async function discoverAdvertised(
  client: AxiosInstance,
  baseUrl: string,
  initial: ProbeTarget[],
  projectPath?: string,
): Promise<Advertised> {
  const responses = new Map<string, Resp | null>();
  const get = async (p: string): Promise<Resp | null> => {
    try {
      return await client.get(p);
    } catch {
      return null;
    }
  };

  const seen = new Set(initial.map((t) => keyOf(t.path)));
  const queue: Candidate[] = [];
  const enqueue = (c: Candidate): void => {
    const k = keyOf(c.path);
    if (seen.has(k)) return;
    const skip = advertisedSkipReason(c.path);
    if (skip) {
      logger.debug(`[advertised] not requested: ${c.path} (${skip})`);
      return;
    }
    seen.add(k);
    queue.push(c);
  };
  const advertise = (href: string, from: string, how: string, kind?: DocKind): void => {
    const p = toLocalPath(href, from, baseUrl);
    if (p) enqueue({ path: p, why: [`advertised by GET ${from} (${how})`], guarded: false, ...(kind ? { kind } : {}) });
  };

  /** Documents are read wherever they were fetched; HTML pages only at depth 0. */
  const readDocuments = (from: string, res: Resp, kind: DocKind | undefined): void => {
    if (res.status < 200 || res.status >= 300) return;
    const text = textOf(res);
    const lower = from.toLowerCase();
    if (text !== null && lower === '/robots.txt') {
      for (const url of robotsSitemaps(text)) advertise(url, from, 'Sitemap line', 'sitemap');
    }
    if (text !== null && (kind === 'sitemap' || /(^|\/)sitemap[^/]*\.xml$/.test(lower))) {
      const { locs, index } = sitemapLocs(text);
      for (const url of locs) advertise(url, from, 'sitemap entry', index ? 'sitemap' : undefined);
    }
    const spec = specDocument(res);
    if (spec) {
      const { targets } = EndpointMapper.plan(routesFromSpecDocument(spec, `GET ${from}`));
      for (const t of targets) {
        enqueue({
          path: t.path,
          why: [`advertised by GET ${from} (OpenAPI/Swagger paths)`, t.guarded ? 'requires auth per the spec' : 'no auth required per the spec'],
          guarded: t.guarded,
        });
      }
    }
  };

  for (const t of initial) responses.set(t.path, await get(t.path));

  // Documents and header links first so a long link list cannot starve them.
  for (const t of initial) {
    const res = responses.get(t.path);
    if (!res || res.status < 200 || res.status >= 300) continue;
    for (const l of linkHeaderTargets(res.headers['link'])) advertise(l.url, t.path, `Link header rel=${l.rel}`, LINK_RELS[l.rel]);
    readDocuments(t.path, res, undefined);
  }
  if (projectPath) {
    const ev = staticEvidence(projectPath);
    if (ev.robots) enqueue({ path: '/robots.txt', why: [`robots.txt exists in the project (${ev.robots})`], guarded: false });
    if (ev.sitemap) enqueue({ path: '/sitemap.xml', why: [`sitemap.xml exists in the project (${ev.sitemap})`], guarded: false, kind: 'sitemap' });
  }
  for (const t of initial) {
    const res = responses.get(t.path);
    if (!res || res.status < 200 || res.status >= 300) continue;
    const type = String(res.headers['content-type'] ?? '');
    const html = textOf(res);
    if (html === null || (type && !/html/i.test(type))) continue;
    for (const href of extractHrefs(html)) advertise(href, t.path, 'link');
  }

  const targets: ProbeTarget[] = [];
  let requested = 0;
  while (queue.length > 0 && requested < MAX_ADVERTISED) {
    const c = queue.shift()!;
    requested++;
    const res = await get(c.path);
    responses.set(c.path, res);
    if (!res) {
      logger.debug(`[advertised] ${c.path}: no response, not checked`);
      continue;
    }
    const evidence = adminEvidence({ path: c.path });
    targets.push({ method: 'GET', path: c.path, guarded: c.guarded, sensitive: evidence.length > 0, why: [...c.why, ...evidence] });
    readDocuments(c.path, res, c.kind);
  }
  if (queue.length > 0) {
    logger.debug(`[advertised] ${queue.length} more advertised path(s) not requested: limit of ${MAX_ADVERTISED} new paths per scan`);
  }
  return { targets, responses };
}
