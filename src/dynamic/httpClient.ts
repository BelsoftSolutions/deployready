/**
 * Shared HTTP client for dynamic testing. Enforces the tool's safety rules:
 * - Only loopback targets are allowed (SSRF guard — we never probe remote hosts).
 * - Hard per-request timeout.
 * - Never throws on HTTP error status; we want to inspect 4xx/5xx.
 */
import axios from 'axios';
import type { AxiosInstance, AxiosResponse } from 'axios';

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);
const TIMEOUT_MS = 8000;

export function assertLoopback(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid URL: ${rawUrl}`);
  }
  const host = url.hostname;
  const isLoopback = LOOPBACK_HOSTS.has(host) || host.endsWith('.localhost');
  if (!isLoopback) {
    throw new Error(
      `Refusing to test non-loopback host "${host}". DeployReady only probes apps on your own machine.`,
    );
  }
  return url;
}

export function createClient(baseUrl: string): AxiosInstance {
  assertLoopback(baseUrl);
  return axios.create({
    baseURL: baseUrl,
    timeout: TIMEOUT_MS,
    maxRedirects: 0,
    // Inspect every status ourselves; don't throw on 4xx/5xx.
    validateStatus: () => true,
    // Cap response size so a huge body can't exhaust memory.
    maxContentLength: 5 * 1024 * 1024,
    headers: { 'User-Agent': 'DeployReady-Scanner/0.1' },
  });
}

export type Resp = AxiosResponse;
