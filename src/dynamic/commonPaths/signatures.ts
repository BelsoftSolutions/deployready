/**
 * Fixed table of the 16 paths the opt-in common-path probe may request, with the
 * content signature that must hold before a 200 counts as a finding
 * (docs/COMMON-PATH-PROBE-DESIGN.md section 1.4). Signatures return key names and counts
 * as evidence, never values.
 */
import type { Severity } from '../../types';
import { detectSecret } from '../../utils/redact';

export interface SignatureInput {
  body: Buffer;
  text: string;
  contentType: string;
}

export interface SignatureMatch {
  severity: Severity;
  evidence: string;
}

/**
 * How the C4 "HTML where a data file is expected" check applies:
 * - data: text data file; HTML (content type or leading `<`) is rejected.
 * - json: JSON document; HTML is rejected.
 * - html: HTML is the expected content; no HTML check.
 * - binary: binary file; no HTML check (the magic bytes are the signature).
 */
export type ExpectedKind = 'data' | 'json' | 'html' | 'binary';

export interface PathSignature {
  id: string;
  paths: string[];
  /** Used in the finding title, before the "(guessed path, lower confidence)" label. */
  what: string;
  expected: ExpectedKind;
  /** Highest severity this row can ever produce (the table's severity). */
  ceiling: Severity;
  /** True when the content itself proves a real exposure, so a critical is allowed. */
  conclusive: boolean;
  /** Short statement of the content that proves the match. */
  proof: string;
  recommendation: string;
  owasp: string;
  cwe: string;
  match(input: SignatureInput): SignatureMatch | null;
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

/** The lower of two severities. */
export function capSeverity(wanted: Severity, ceiling: Severity): Severity {
  return SEVERITY_RANK[wanted] <= SEVERITY_RANK[ceiling] ? wanted : ceiling;
}

export function looksLikeHtml(text: string, contentType: string): boolean {
  return /text\/html|application\/xhtml/i.test(contentType) || text.trimStart().startsWith('<');
}

function looksLikeJson(text: string, contentType: string): boolean {
  return /json/i.test(contentType) || /^\s*[{[]/.test(text);
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(text);
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

// ---- row 1: .env -----------------------------------------------------------

const ENV_LINE = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.+)$/;
const SECRET_KEY = /SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|API_?KEY|ACCESS_?KEY|DATABASE_URL|CREDENTIAL/i;
const PLACEHOLDER_VALUE = /^(?:changeme|your[_-].*|x{3,}.*|<.*>|\.\.\.|example.*|\$\{.*\})$/i;
const ENV_MAX_BYTES = 64 * 1024;
const MAX_LISTED_KEYS = 10;

function unquote(value: string): string {
  const v = value.trim();
  return v.length >= 2 && /^(['"]).*\1$/.test(v) ? v.slice(1, -1).trim() : v;
}

function matchEnv({ body, text }: SignatureInput): SignatureMatch | null {
  if (body.length > ENV_MAX_BYTES) return null;
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  const pairs: { key: string; value: string }[] = [];
  for (const line of lines) {
    const m = ENV_LINE.exec(line);
    if (m) pairs.push({ key: m[1] ?? '', value: unquote(m[2] ?? '') });
  }
  if (pairs.length < 1 || pairs.length * 2 < lines.length) return null;

  let critical = false;
  for (const { key, value } of pairs) {
    if (detectSecret(value) === 'high') critical = true;
    else if (SECRET_KEY.test(key) && value !== '' && !PLACEHOLDER_VALUE.test(value)) critical = true;
  }
  const keys = pairs.map((p) => p.key);
  const shown = keys.slice(0, MAX_LISTED_KEYS).join(', ');
  const more = keys.length > MAX_LISTED_KEYS ? ` (+${keys.length - MAX_LISTED_KEYS} more)` : '';
  return {
    severity: critical ? 'critical' : 'warning',
    evidence: `${pairs.length} KEY=VALUE line${pairs.length === 1 ? '' : 's'}; keys: ${shown}${more}; values not shown`,
  };
}

// ---- row 2: .git/config ----------------------------------------------------

function matchGitConfig({ text }: SignatureInput): SignatureMatch | null {
  if (!/^\s*\[core\]/m.test(text)) return null;
  const remotes = (text.match(/^\s*\[remote "/gm) ?? []).length;
  const branches = (text.match(/^\s*\[branch "/gm) ?? []).length;
  if (!/repositoryformatversion/.test(text) && remotes === 0 && branches === 0) return null;
  return {
    severity: 'critical',
    evidence: `git config with [core], ${remotes} remote section(s), ${branches} branch section(s); contents not shown`,
  };
}

// ---- row 3: .npmrc ---------------------------------------------------------

function matchNpmrc({ text }: SignatureInput): SignatureMatch | null {
  const re = /^(?:\/\/\S+:)?_(authToken|auth|password)\s*=\s*\S+/;
  const kinds = new Set<string>();
  let count = 0;
  for (const line of text.split(/\r?\n/)) {
    const m = re.exec(line.trim());
    if (m) {
      count++;
      kinds.add(`_${m[1]}`);
    }
  }
  if (count === 0) return null;
  return {
    severity: 'critical',
    evidence: `${count} registry credential line(s); keys: ${[...kinds].join(', ')}; values not shown`,
  };
}

// ---- row 4: SQL dump -------------------------------------------------------

function matchSqlDump({ body }: SignatureInput): SignatureMatch | null {
  const head = body.subarray(0, 4096).toString('utf8');
  const header = /-- MySQL dump|-- PostgreSQL database dump/.test(head);
  const statements = head.split(/\r?\n/).filter((l) => l.trimEnd().endsWith(';')).length;
  const ddl = /CREATE TABLE|INSERT INTO/i.test(head) && statements >= 2;
  if (!header && !ddl) return null;
  return {
    severity: 'critical',
    evidence: `${header ? 'database dump header' : 'SQL statements'}; ${statements} statement line(s) in the first 4 KB; contents not shown`,
  };
}

// ---- row 5: SQLite ---------------------------------------------------------

const SQLITE_MAGIC = Buffer.from('SQLite format 3\0', 'latin1');

function matchSqlite({ body }: SignatureInput): SignatureMatch | null {
  if (body.length < SQLITE_MAGIC.length || !body.subarray(0, SQLITE_MAGIC.length).equals(SQLITE_MAGIC)) return null;
  return { severity: 'critical', evidence: 'SQLite database file header (16 bytes); contents not shown' };
}

// ---- row 6: /actuator/env --------------------------------------------------

function matchActuatorEnv({ text }: SignatureInput): SignatureMatch | null {
  const obj = parseJsonObject(text);
  if (!obj) return null;
  const sources = obj.propertySources;
  const profiles = obj.activeProfiles;
  if (!Array.isArray(sources) && !Array.isArray(profiles)) return null;
  const critical = detectSecret(text) === 'high';
  return {
    severity: critical ? 'critical' : 'warning',
    evidence:
      `environment document: ${Array.isArray(sources) ? sources.length : 0} property source(s), ` +
      `${Array.isArray(profiles) ? profiles.length : 0} active profile(s)` +
      `${critical ? '; an unmasked secret-shaped value is present' : ''}; values not shown`,
  };
}

// ---- row 7: /actuator ------------------------------------------------------

const ACTUATOR_LINKS = ['health', 'env', 'beans', 'mappings', 'info'];

function hasHref(v: unknown): boolean {
  return isObj(v) && typeof v.href === 'string';
}

function matchActuator({ text }: SignatureInput): SignatureMatch | null {
  const obj = parseJsonObject(text);
  const links = obj?._links;
  if (!isObj(links) || !hasHref(links.self)) return null;
  const present = ACTUATOR_LINKS.filter((k) => k in links);
  if (present.length === 0 || !present.every((k) => hasHref(links[k]))) return null;
  return { severity: 'info', evidence: `actuator index linking: ${present.join(', ')}` };
}

// ---- rows 8, 10, 11: HTML status pages -------------------------------------

function matchPhpinfo({ text }: SignatureInput): SignatureMatch | null {
  const ok = /<title>phpinfo\(\)<\/title>/i.test(text) || (text.includes('PHP Version') && text.includes('phpinfo()'));
  return ok ? { severity: 'warning', evidence: 'phpinfo() page markers present; contents not shown' } : null;
}

function matchPprof({ text }: SignatureInput): SignatureMatch | null {
  return text.includes('Types of profiles available')
    ? { severity: 'warning', evidence: 'Go pprof index page ("Types of profiles available")' }
    : null;
}

function matchServerStatus({ text }: SignatureInput): SignatureMatch | null {
  return text.includes('Apache Server Status for')
    ? { severity: 'warning', evidence: 'Apache server-status page ("Apache Server Status for")' }
    : null;
}

// ---- row 9: /metrics -------------------------------------------------------

function matchMetrics({ text }: SignatureInput): SignatureMatch | null {
  const helped = new Set<string>();
  for (const m of text.matchAll(/^# HELP (\S+)(?:\s.*)?$/gm)) helped.add(m[1] ?? '');
  let shared = 0;
  for (const m of text.matchAll(/^# TYPE (\S+) (?:counter|gauge|histogram|summary|untyped)\s*$/gm)) {
    if (helped.has(m[1] ?? '')) shared++;
  }
  return shared > 0 ? { severity: 'info', evidence: `Prometheus exposition format; ${shared} metric(s) with HELP and TYPE` } : null;
}

// ---- row 12: /console ------------------------------------------------------

function matchConsole({ text }: SignatureInput): SignatureMatch | null {
  const werkzeug = text.includes('Werkzeug') || text.includes('__debugger__');
  if (!werkzeug) return null;
  if (text.includes('Console Locked')) {
    return { severity: 'warning', evidence: 'Werkzeug debugger console page, PIN-locked' };
  }
  if (text.includes('Interactive Console')) {
    return { severity: 'critical', evidence: 'Werkzeug debugger console page, unlocked (interactive console)' };
  }
  return null;
}

// ---- row 13: /admin --------------------------------------------------------

const ADMIN_HEADING = /\badmin(istrat\w*)?\b|dashboard|control panel|backoffice/i;

function stripTags(s: string): string {
  return s.replace(/<[^>]{0,200}>/g, ' ').replace(/\s+/g, ' ').trim();
}

function matchAdmin({ text, contentType }: SignatureInput): SignatureMatch | null {
  if (looksLikeJson(text, contentType)) return null;
  const title = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(text);
  const h1 = /<h1[^>]*>([\s\S]{0,300}?)<\/h1>/i.exec(text);
  const hit = [title?.[1], h1?.[1]].some((t) => t !== undefined && ADMIN_HEADING.test(stripTags(t)));
  return hit ? { severity: 'warning', evidence: 'HTML page whose title or first heading names an admin area' } : null;
}

// ---- the table -------------------------------------------------------------

export const SIGNATURES: PathSignature[] = [
  {
    id: 'env',
    paths: ['/.env', '/.env.local', '/.env.production'],
    what: 'Exposed environment file',
    expected: 'data',
    ceiling: 'critical',
    conclusive: true,
    proof: 'KEY=VALUE lines',
    recommendation: 'Never serve dotfiles. Block them at the web server, keep .env out of the public/static directory, and rotate every secret it contained.',
    owasp: 'A02:2025',
    cwe: 'CWE-538',
    match: matchEnv,
  },
  {
    id: 'git-config',
    paths: ['/.git/config'],
    what: 'Exposed git repository',
    expected: 'data',
    ceiling: 'critical',
    conclusive: true,
    proof: 'git config sections',
    recommendation: 'Do not deploy the .git directory. Block /.git at the web server and rotate any credentials stored in the repository history.',
    owasp: 'A02:2025',
    cwe: 'CWE-527',
    match: matchGitConfig,
  },
  {
    id: 'npmrc',
    paths: ['/.npmrc'],
    what: 'Exposed .npmrc with registry credentials',
    expected: 'data',
    ceiling: 'critical',
    conclusive: true,
    proof: 'registry credential lines',
    recommendation: 'Do not serve .npmrc. Revoke and rotate the registry token and keep the file out of the public directory.',
    owasp: 'A02:2025',
    cwe: 'CWE-538',
    match: matchNpmrc,
  },
  {
    id: 'sql-dump',
    paths: ['/backup.sql', '/dump.sql'],
    what: 'Exposed database dump',
    expected: 'data',
    ceiling: 'critical',
    conclusive: true,
    proof: 'SQL dump content',
    recommendation: 'Remove database dumps from the web root, store backups outside it, and treat the data as exposed.',
    owasp: 'A02:2025',
    cwe: 'CWE-530',
    match: matchSqlDump,
  },
  {
    id: 'sqlite',
    paths: ['/db.sqlite3'],
    what: 'Exposed SQLite database',
    expected: 'binary',
    ceiling: 'critical',
    conclusive: true,
    proof: 'SQLite file header',
    recommendation: 'Keep database files outside the web root and treat the data as exposed.',
    owasp: 'A02:2025',
    cwe: 'CWE-530',
    match: matchSqlite,
  },
  {
    id: 'actuator-env',
    paths: ['/actuator/env'],
    what: 'Exposed Spring Boot /actuator/env',
    expected: 'json',
    ceiling: 'critical',
    conclusive: true,
    proof: 'actuator environment JSON',
    recommendation: 'Restrict actuator endpoints to a management port or require authentication, and do not expose env.',
    owasp: 'A05:2025',
    cwe: 'CWE-215',
    match: matchActuatorEnv,
  },
  {
    id: 'actuator',
    paths: ['/actuator'],
    what: 'Exposed Spring Boot actuator index',
    expected: 'json',
    ceiling: 'info',
    conclusive: false,
    proof: 'actuator _links index',
    recommendation: 'Expose only the actuator endpoints you need and put them behind authentication or a separate management port.',
    owasp: 'A05:2025',
    cwe: 'CWE-215',
    match: matchActuator,
  },
  {
    id: 'phpinfo',
    paths: ['/phpinfo.php'],
    what: 'Exposed phpinfo() page',
    expected: 'html',
    ceiling: 'warning',
    conclusive: false,
    proof: 'phpinfo() page markers',
    recommendation: 'Delete phpinfo.php from deployed code.',
    owasp: 'A05:2025',
    cwe: 'CWE-200',
    match: matchPhpinfo,
  },
  {
    id: 'metrics',
    paths: ['/metrics'],
    what: 'Exposed Prometheus metrics',
    expected: 'data',
    ceiling: 'info',
    conclusive: false,
    proof: 'Prometheus HELP/TYPE lines',
    recommendation: 'Serve metrics on an internal port or behind authentication.',
    owasp: 'A05:2025',
    cwe: 'CWE-200',
    match: matchMetrics,
  },
  {
    id: 'pprof',
    paths: ['/debug/pprof/'],
    what: 'Exposed Go pprof profiler',
    expected: 'html',
    ceiling: 'warning',
    conclusive: false,
    proof: 'pprof index page',
    recommendation: 'Do not register pprof handlers on a public listener; bind them to localhost or an internal port.',
    owasp: 'A05:2025',
    cwe: 'CWE-489',
    match: matchPprof,
  },
  {
    id: 'server-status',
    paths: ['/server-status'],
    what: 'Exposed Apache server-status',
    expected: 'html',
    ceiling: 'warning',
    conclusive: false,
    proof: 'Apache server-status page',
    recommendation: 'Restrict mod_status to localhost or remove it.',
    owasp: 'A05:2025',
    cwe: 'CWE-200',
    match: matchServerStatus,
  },
  {
    id: 'console',
    paths: ['/console'],
    what: 'Exposed Werkzeug debugger console',
    expected: 'html',
    ceiling: 'critical',
    conclusive: true,
    proof: 'Werkzeug console page',
    recommendation: 'Never run the Werkzeug debugger (Flask debug mode) in production; it allows remote code execution.',
    owasp: 'A05:2025',
    cwe: 'CWE-489',
    match: matchConsole,
  },
  {
    id: 'admin',
    paths: ['/admin'],
    what: 'Admin page reachable without login',
    expected: 'html',
    ceiling: 'warning',
    conclusive: false,
    proof: 'an admin-titled HTML page',
    recommendation: 'Confirm this page requires authentication and authorization.',
    owasp: 'A01:2025',
    cwe: 'CWE-284',
    match: matchAdmin,
  },
];

export interface ProbePath {
  path: string;
  signature: PathSignature;
}

/** The 16 probed paths in table order. */
export const PROBE_PATHS: ProbePath[] = SIGNATURES.flatMap((signature) =>
  signature.paths.map((path) => ({ path, signature })),
);
