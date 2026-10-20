/**
 * Routes declared in the project's own OpenAPI/Swagger files on disk. Nothing
 * here makes a request: the spec is evidence the project itself wrote. A file
 * that cannot be read faithfully is skipped with a visible note, never guessed.
 */
import { FileWalker } from '../utils/FileWalker';
import type { WalkedFile } from '../utils/FileWalker';
import { assertLoopback } from '../dynamic/httpClient';
import type { Route } from '../types';
import { joinPath, normalizeRoutePath } from './pathUtil';
import { parseYaml, YamlFlow, YamlUnsupported } from './miniYaml';

export const MAX_SPEC_FILES = 5;
const MAX_ROUTES_PER_SPEC = 2000;
const METHODS = new Set(['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']);

export interface SpecRead {
  routes: Route[];
  /** Spec files that produced a route list (relative paths). */
  specFiles: string[];
  /** Visible info lines: skipped files and why. */
  notes: string[];
}

class SpecUnreadable extends Error {}

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && !(v instanceof YamlFlow);
}

function readable<T>(v: T): Exclude<T, YamlFlow> {
  if (v instanceof YamlFlow) throw new SpecUnreadable('it uses flow-style YAML ({...} / [...]) where DeployReady\'s small YAML reader needs block style');
  return v as Exclude<T, YamlFlow>;
}

export async function readOpenApiRoutes(
  specFiles: WalkedFile[],
  skippedSpecs: { relPath: string; reason: string }[] = [],
): Promise<SpecRead> {
  const out: SpecRead = { routes: [], specFiles: [], notes: [] };
  for (const s of skippedSpecs) out.notes.push(skipNote(s.relPath, s.reason));

  const ordered = [...specFiles].sort(
    (a, b) => a.relPath.split('/').length - b.relPath.split('/').length || a.relPath.localeCompare(b.relPath),
  );
  if (ordered.length > MAX_SPEC_FILES) {
    out.notes.push(
      `Found ${ordered.length} OpenAPI/Swagger files; reading the first ${MAX_SPEC_FILES} (${ordered
        .slice(MAX_SPEC_FILES)
        .map((f) => f.relPath)
        .join(', ')} not read).`,
    );
  }

  const byKey = new Map<string, Route>();
  for (const file of ordered.slice(0, MAX_SPEC_FILES)) {
    let routes: Route[];
    try {
      routes = extractRoutes(parseSpec(file, await FileWalker.read(file)), file.relPath);
    } catch (err) {
      out.notes.push(skipNote(file.relPath, describe(err)));
      continue;
    }
    out.specFiles.push(file.relPath);
    for (const r of routes) {
      const key = `${r.method} ${normalizeRoutePath(r.path)}`;
      const prior = byKey.get(key);
      if (prior) {
        prior.specFiles = [...new Set([...(prior.specFiles ?? []), r.file])];
        continue;
      }
      byKey.set(key, r);
      out.routes.push(r);
    }
  }
  return out;
}

/** Routes of an OpenAPI/Swagger document a running app served (already parsed JSON); [] when it cannot be read faithfully. */
export function routesFromSpecDocument(doc: unknown, label: string): Route[] {
  try {
    return extractRoutes(doc, label);
  } catch {
    return [];
  }
}

function skipNote(file: string, reason: string): string {
  return `OpenAPI/Swagger file ${file} not used: ${reason}. No routes were guessed from it.`;
}

function describe(err: unknown): string {
  if (err instanceof SpecUnreadable) return err.message;
  if (err instanceof YamlUnsupported) return `it uses YAML that DeployReady's small reader does not support (${err.message})`;
  if (err instanceof SyntaxError) return 'it is not valid JSON';
  return 'it could not be read';
}

function parseSpec(file: WalkedFile, text: string): unknown {
  return /\.json$/i.test(file.relPath) ? JSON.parse(text) : parseYaml(text);
}

function extractRoutes(doc: unknown, file: string): Route[] {
  const version = isObj(doc) ? (doc.openapi ?? doc.swagger) : undefined;
  if (!isObj(doc) || (typeof version !== 'string' && typeof version !== 'number')) {
    throw new SpecUnreadable('it has no "openapi" or "swagger" version field');
  }
  const paths = readable(doc.paths);
  if (!isObj(paths)) throw new SpecUnreadable('it has no "paths" section');

  const base = basePathOf(doc);
  const globalSecurity = doc.security;
  const routes: Route[] = [];
  for (const [pathKey, item] of Object.entries(paths)) {
    if (!pathKey.startsWith('/') || /[\s?#]/.test(pathKey)) continue;
    const pathItem = readable(item);
    if (!isObj(pathItem)) continue;
    for (const [key, opValue] of Object.entries(pathItem)) {
      if (!METHODS.has(key.toLowerCase())) continue;
      const op = readable(opValue);
      const security = isObj(op) && 'security' in op ? op.security : globalSecurity;
      routes.push({
        method: key.toUpperCase(),
        path: joinPath(base, pathKey),
        file,
        guarded: requiresAuth(security),
        source: 'openapi',
      });
      if (routes.length >= MAX_ROUTES_PER_SPEC) throw new SpecUnreadable(`it declares more than ${MAX_ROUTES_PER_SPEC} operations`);
    }
  }
  return routes;
}

/** Guarded = a non-empty security requirement list in which no alternative is the empty `{}` (anonymous allowed). */
function requiresAuth(security: unknown): boolean {
  if (security instanceof YamlFlow) {
    const compact = security.raw.replace(/\s+/g, '');
    if (compact === '[]') return false;
    if (/^\[\{[^{}]*\}(,\{[^{}]*\})*\]$/.test(compact) && !/\{\}/.test(compact)) return true;
    throw new SpecUnreadable('its "security" uses flow-style YAML that DeployReady\'s small YAML reader cannot interpret');
  }
  if (!Array.isArray(security) || security.length === 0) return false;
  return security.every((alt) => {
    const a = readable(alt);
    return isObj(a) && Object.keys(a).length > 0;
  });
}

function basePathOf(doc: Obj): string {
  if ('swagger' in doc) {
    const bp = readable(doc.basePath);
    return typeof bp === 'string' ? cleanBase(bp) : '';
  }
  const servers = readable(doc.servers);
  if (!Array.isArray(servers) || servers.length === 0) return '';
  const first = readable(servers[0]);
  if (!isObj(first)) return '';
  const rawUrl = readable(first.url);
  if (typeof rawUrl !== 'string') return '';
  const url = rawUrl.replace(/\{([^{}]*)\}/g, (_m, name: string) => {
    const vars = readable(first.variables);
    const v = isObj(vars) ? readable(vars[name]) : undefined;
    const def = isObj(v) ? readable(v.default) : undefined;
    if (typeof def !== 'string') throw new SpecUnreadable(`its server URL uses the variable {${name}} without a default`);
    return def;
  });
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
    try {
      return cleanBase(assertLoopback(url).pathname);
    } catch {
      return ''; // a non-loopback host: its path is not the local mount
    }
  }
  if (url.startsWith('//')) return '';
  return cleanBase(url);
}

function cleanBase(p: string): string {
  const path = p.split(/[?#]/)[0] ?? '';
  if (/[{}]/.test(path)) throw new SpecUnreadable('its base path contains a template variable');
  const joined = joinPath('', path);
  return joined === '/' ? '' : joined;
}
