/**
 * Named test identities for the policy-driven authorization engine (0.6).
 *
 * An identity is "who is calling": anonymous, a normal user, a second user, an
 * admin, a user of another tenant, ... Each one is an `IdentityProvider`, which
 * only has to say who it is and produce the request headers that authenticate
 * as it. Static bearer tokens and tokens read from an environment variable are
 * built in; a login-session provider (e.g. a browser login) is plugged in from
 * outside through `registerSessionProvider`, so this module never drives a
 * browser itself.
 *
 * Config (`.deployready.json` → `active.identities`):
 *
 *   { "name": "alice", "role": "user", "tenant": "acme", "tokenEnv": "ALICE_TOKEN",
 *     "params": { "userId": "u_alice", "org": "acme" },
 *     "objects": { "invoices": { "id": "inv_1" } } }
 *
 * `params` / `objects` name the identity's OWN records, so the engine can build
 * "alice asks for bob's invoice" without inventing an id. Values are never
 * guessed: a route whose parameters cannot be filled for an identity is untested.
 *
 * Safety: a literal `token` in a project file is accepted but discouraged
 * (prefer `tokenEnv`); `tokenEnv` must name a variable that looks like a
 * credential for this purpose (contains TOKEN, JWT, SESSION, COOKIE or AUTH),
 * so a shared config cannot make the scanner pick up an unrelated secret.
 * Header values are never written to a report; proofs name them `$<NAME>_AUTH`.
 */
import { decodeJwt } from './jwt';

/** What the engine needs from an identity. Implemented by static/env tokens here and by session providers elsewhere. */
export interface IdentityProvider {
  /** Unique name, e.g. "alice", "admin", "anonymous". */
  name: string;
  /** Role used to look up the policy, e.g. "anonymous", "user", "admin". */
  role: string;
  /** Tenant / organization the identity belongs to, when the app is multi-tenant. */
  tenant?: string;
  /** Headers that authenticate a request as this identity ({} for anonymous). */
  headers(): Promise<Record<string, string>>;
  /** Optional: route-parameter values of the identity's own records (param name → value). */
  params?: Record<string, string | number>;
  /** Optional: per-resource own-record parameters (resource name → param name → value). */
  objects?: Record<string, Record<string, string | number>>;
  /** Optional: JWT claims, when the credential is a JWT (used to fill user/tenant params). */
  claims?: Record<string, unknown>;
  /** Optional: release resources (a browser, a session) after the run. */
  dispose?(): Promise<void>;
}

/** One entry of `active.identities` in the config. */
export interface IdentityConfig {
  name: string;
  role: string;
  tenant?: string;
  /** Literal bearer token (discouraged in a committed file; prefer tokenEnv). */
  token?: string;
  /** Name of an environment variable holding the bearer token. */
  tokenEnv?: string;
  /** Login-session settings, handed to the registered session provider for `session.provider`. */
  session?: SessionConfig;
  params?: Record<string, string | number>;
  objects?: Record<string, Record<string, string | number>>;
}

export interface SessionConfig {
  /** Which registered provider builds this session (default "playwright"). */
  provider?: string;
  [key: string]: unknown;
}

/** Builds a session identity from its config; registered by the module that implements it. */
export type SessionProviderFactory = (identity: IdentityConfig, ctx: { baseUrl?: string; projectPath?: string }) => Promise<IdentityProvider>;

const sessionFactories = new Map<string, SessionProviderFactory>();

/** Register a provider for `session` identities (e.g. "playwright"). Re-registering replaces it. */
export function registerSessionProvider(kind: string, factory: SessionProviderFactory): void {
  sessionFactories.set(kind.trim().toLowerCase(), factory);
}

/** Test hook: forget registered session providers. */
export function clearSessionProviders(): void {
  sessionFactories.clear();
}

export const ANONYMOUS_ROLE = 'anonymous';
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/;
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const ENV_PURPOSE_RE = /TOKEN|JWT|SESSION|COOKIE|AUTH/i;

/** Placeholder used in proofs instead of an identity's credential. */
export function authPlaceholder(name: string): string {
  return `$${name.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_AUTH`;
}

function scalarMap(v: unknown, where: string, problems: string[]): Record<string, string | number> | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    problems.push(`${where} must be an object of name → value.`);
    return undefined;
  }
  const out: Record<string, string | number> = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    if (k.startsWith('_')) continue;
    if (typeof val === 'string' || typeof val === 'number') out[k] = val;
    else problems.push(`${where}.${k} must be a string or number.`);
  }
  return out;
}

/** Validate `active.identities`. Invalid entries are dropped with a problem message (never guessed). */
export function parseIdentityConfigs(raw: unknown): { identities: IdentityConfig[]; problems: string[] } {
  const problems: string[] = [];
  const identities: IdentityConfig[] = [];
  if (raw === undefined) return { identities, problems };
  if (!Array.isArray(raw)) return { identities, problems: ['active.identities must be an array.'] };
  const names = new Set<string>();
  raw.forEach((entry, i) => {
    const at = `active.identities[${i}]`;
    if (typeof entry !== 'object' || entry === null) {
      problems.push(`${at} must be an object.`);
      return;
    }
    const e = entry as Record<string, unknown>;
    const name = typeof e.name === 'string' ? e.name.trim() : '';
    if (!NAME_RE.test(name)) {
      problems.push(`${at}.name must be 1-40 letters, digits, "-", "_" or "." (got ${JSON.stringify(e.name)}).`);
      return;
    }
    if (names.has(name.toLowerCase())) {
      problems.push(`${at}: duplicate identity name "${name}".`);
      return;
    }
    const role = typeof e.role === 'string' && e.role.trim() ? e.role.trim() : name === 'anonymous' ? ANONYMOUS_ROLE : '';
    if (!role) {
      problems.push(`${at} ("${name}") needs a role.`);
      return;
    }
    const sources = ['token', 'tokenEnv', 'session'].filter((k) => e[k] !== undefined);
    if (sources.length > 1) {
      problems.push(`${at} ("${name}") must use only one of token, tokenEnv, session.`);
      return;
    }
    if (sources.length === 0 && role !== ANONYMOUS_ROLE) {
      problems.push(`${at} ("${name}") has no credential (token, tokenEnv or session); only the anonymous role may have none.`);
      return;
    }
    if (e.token !== undefined && (typeof e.token !== 'string' || !e.token.trim())) {
      problems.push(`${at}.token must be a non-empty string.`);
      return;
    }
    if (e.tokenEnv !== undefined) {
      if (typeof e.tokenEnv !== 'string' || !ENV_NAME_RE.test(e.tokenEnv)) {
        problems.push(`${at}.tokenEnv must be an environment variable name.`);
        return;
      }
      if (!ENV_PURPOSE_RE.test(e.tokenEnv)) {
        problems.push(`${at}.tokenEnv "${e.tokenEnv}" must contain TOKEN, JWT, SESSION, COOKIE or AUTH (so an unrelated secret is never read).`);
        return;
      }
    }
    if (e.session !== undefined && (typeof e.session !== 'object' || e.session === null || Array.isArray(e.session))) {
      problems.push(`${at}.session must be an object.`);
      return;
    }
    const params = scalarMap(e.params, `${at}.params`, problems);
    let objects: Record<string, Record<string, string | number>> | undefined;
    if (e.objects !== undefined) {
      if (typeof e.objects !== 'object' || e.objects === null || Array.isArray(e.objects)) problems.push(`${at}.objects must be an object.`);
      else {
        objects = {};
        for (const [res, m] of Object.entries(e.objects as Record<string, unknown>)) {
          if (res.startsWith('_')) continue;
          const parsed = scalarMap(m, `${at}.objects.${res}`, problems);
          if (parsed) objects[res] = parsed;
        }
      }
    }
    names.add(name.toLowerCase());
    identities.push({
      name,
      role,
      ...(typeof e.tenant === 'string' && e.tenant.trim() ? { tenant: e.tenant.trim() } : typeof e.tenant === 'number' ? { tenant: String(e.tenant) } : {}),
      ...(typeof e.token === 'string' ? { token: e.token.trim() } : {}),
      ...(typeof e.tokenEnv === 'string' ? { tokenEnv: e.tokenEnv } : {}),
      ...(e.session ? { session: e.session as SessionConfig } : {}),
      ...(params ? { params } : {}),
      ...(objects ? { objects } : {}),
    });
  });
  return { identities, problems };
}

/** A bearer-token identity (static token or one read from the environment). */
export function bearerIdentity(cfg: Omit<IdentityConfig, 'tokenEnv' | 'session'> & { token: string }): IdentityProvider {
  const token = cfg.token;
  const claims = decodeJwt(token)?.payload;
  return {
    name: cfg.name,
    role: cfg.role,
    ...(cfg.tenant ? { tenant: cfg.tenant } : {}),
    ...(cfg.params ? { params: cfg.params } : {}),
    ...(cfg.objects ? { objects: cfg.objects } : {}),
    ...(claims ? { claims } : {}),
    headers: async () => ({ Authorization: `Bearer ${token}` }),
  };
}

/** The anonymous identity: no credentials at all. */
export function anonymousIdentity(name = 'anonymous'): IdentityProvider {
  return { name, role: ANONYMOUS_ROLE, headers: async () => ({}) };
}

export interface ResolvedIdentity {
  name: string;
  role: string;
  tenant?: string;
  provider?: IdentityProvider;
  /** Why the identity could not be built (then it is untested). */
  unavailable?: string;
}

export interface ResolveIdentityOptions {
  env?: NodeJS.ProcessEnv;
  /** --token / --token-b from the command line, added as identities "token" and "token-b" (role "user"). */
  cliToken?: string;
  cliTokenB?: string;
  baseUrl?: string;
  projectPath?: string;
  /**
   * Plan only (--dry-run / passive): no login is performed and no credential is
   * read for sending; every configured identity gets a stub whose headers() throws.
   */
  planOnly?: boolean;
}

function stubProvider(c: IdentityConfig): IdentityProvider {
  return {
    name: c.name,
    role: c.role,
    ...(c.tenant ? { tenant: c.tenant } : {}),
    ...(c.params ? { params: c.params } : {}),
    ...(c.objects ? { objects: c.objects } : {}),
    headers: async () => {
      throw new Error('plan-only identity: nothing is sent in a dry run');
    },
  };
}

/**
 * Build providers for the configured identities (+ the CLI tokens). An identity
 * that cannot be built (missing env var, no session provider registered, login
 * failed) is kept with an `unavailable` reason so the matrix shows it untested.
 * An "anonymous" identity is always present.
 */
export async function resolveIdentities(configs: IdentityConfig[], opts: ResolveIdentityOptions = {}): Promise<ResolvedIdentity[]> {
  const env = opts.env ?? process.env;
  const out: ResolvedIdentity[] = [];
  const all = [...configs];
  const taken = new Set(all.map((c) => c.name.toLowerCase()));
  const addCli = (name: string, token: string | undefined) => {
    if (!token || taken.has(name)) return;
    const claims = decodeJwt(token)?.payload;
    const tenant = claims ? firstString(claims, ['org_id', 'organization_id', 'tenant_id', 'tenant', 'workspace_id']) : undefined;
    all.push({ name, role: 'user', token, ...(tenant ? { tenant } : {}) });
    taken.add(name);
  };
  addCli('token', opts.cliToken);
  addCli('token-b', opts.cliTokenB);
  if (!all.some((c) => c.role === ANONYMOUS_ROLE)) all.unshift({ name: taken.has('anonymous') ? 'anon' : 'anonymous', role: ANONYMOUS_ROLE });

  for (const c of all) {
    const base = { name: c.name, role: c.role, ...(c.tenant ? { tenant: c.tenant } : {}) };
    if (opts.planOnly && (c.session || (c.tokenEnv && !env[c.tokenEnv]?.trim()))) {
      out.push({ ...base, provider: stubProvider(c) });
      continue;
    }
    if (c.session) {
      const kind = String(c.session.provider ?? 'playwright').toLowerCase();
      const factory = sessionFactories.get(kind);
      if (!factory) {
        out.push({ ...base, unavailable: `no "${kind}" session provider is available in this build` });
        continue;
      }
      try {
        const p = await factory(c, { baseUrl: opts.baseUrl, projectPath: opts.projectPath });
        out.push({ ...base, provider: { ...p, params: p.params ?? c.params, objects: p.objects ?? c.objects } as IdentityProvider });
      } catch (err) {
        out.push({ ...base, unavailable: `session login failed: ${(err as Error).message}` });
      }
      continue;
    }
    if (c.tokenEnv) {
      const v = env[c.tokenEnv]?.trim();
      if (!v) {
        out.push({ ...base, unavailable: `environment variable ${c.tokenEnv} is not set` });
        continue;
      }
      out.push({ ...base, provider: bearerIdentity({ ...c, token: v }) });
      continue;
    }
    if (c.token) {
      out.push({ ...base, provider: bearerIdentity({ ...c, token: c.token }) });
      continue;
    }
    const anon = anonymousIdentity(c.name);
    out.push({ ...base, provider: { ...anon, ...(c.params ? { params: c.params } : {}), ...(c.objects ? { objects: c.objects } : {}) } });
  }
  return out;
}

function firstString(claims: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = claims[k];
    if (typeof v === 'string' || typeof v === 'number') return String(v);
  }
  return undefined;
}

/** Release every provider that holds resources. Never throws. */
export async function disposeIdentities(ids: ResolvedIdentity[]): Promise<void> {
  for (const i of ids) {
    try {
      await i.provider?.dispose?.();
    } catch {
      /* best effort */
    }
  }
}
