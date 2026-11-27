/**
 * Ownership guard for active (identity-tampering) probes.
 *
 * Default: loopback only, the same bar as the dynamic suite (`assertLoopback`).
 * A non-loopback host is allowed only when the user has explicitly declared that
 * they own it (e.g. `--i-own-this-target staging.example.com`), and only that
 * exact host: no wildcards, no subdomains, no scheme/port/path smuggling. The
 * check is applied to the base URL and again to every request URL, so a request
 * can never leave the declared host.
 */
import { assertLoopback } from '../dynamic/httpClient';

const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/** Lower-case and strip a trailing dot / IPv6 brackets. */
function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '').replace(/^\[(.*)\]$/, '$1');
}

/**
 * Validate the hosts a user declared ownership of. Each must be a bare hostname
 * or IP literal (no scheme, port, path, or wildcard). Throws on anything else so
 * a typo can never widen the scope.
 */
export function parseOwnedHosts(values: string | string[] | undefined): string[] {
  if (values === undefined) return [];
  const list = (Array.isArray(values) ? values : [values])
    .flatMap((v) => v.split(','))
    .map((v) => v.trim())
    .filter(Boolean);
  const out: string[] = [];
  for (const raw of list) {
    const host = normalizeHost(raw);
    const ok = HOST_RE.test(host) || IPV4_RE.test(host) || (host.includes(':') && /^[0-9a-f:]+$/.test(host));
    if (!ok) {
      throw new Error(
        `"${raw}" is not a bare host name. Pass only the host you own (for example staging.example.com): no scheme, port, path or wildcard.`,
      );
    }
    if (!out.includes(host)) out.push(host);
  }
  return out;
}

/**
 * Throw unless `rawUrl` targets a loopback host, or a host listed in
 * `ownedHosts` (the user's explicit ownership confirmation). Returns the URL.
 */
export function assertActiveTarget(rawUrl: string, ownedHosts: readonly string[] = []): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid URL: ${rawUrl}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Refusing to send active probes over ${url.protocol} (only http/https).`);
  }
  if (url.username || url.password) {
    throw new Error('Refusing to send active probes to a URL with embedded credentials.');
  }
  const host = normalizeHost(url.hostname);
  if (ownedHosts.map(normalizeHost).includes(host)) return url;
  try {
    return assertLoopback(rawUrl);
  } catch {
    throw new Error(
      `Refusing to send active (identity-tampering) probes to "${host}": only loopback hosts are allowed unless you confirm you own the target with --i-own-this-target ${host}.`,
    );
  }
}
