/**
 * Deny-by-default environment for CLI children. Only names on the allowlist are passed on.
 * Explicitly NOT passed (so "subscription" really means subscription and no key ever leaks):
 * ANTHROPIC_*, CLAUDE_CODE_OAUTH_TOKEN, OPENAI_*, AWS_*, GITHUB_TOKEN, NODE_OPTIONS, DeployReady keys, ...
 */
const BASE_ALLOW = [
  'PATH', 'PATHEXT', 'SystemRoot', 'windir', 'SystemDrive', 'OS', 'ComSpec',
  'USERPROFILE', 'HOME', 'HOMEDRIVE', 'HOMEPATH', 'USERNAME', 'USER', 'LOGNAME',
  'APPDATA', 'LOCALAPPDATA', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432',
  'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS',
  'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ',
  'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'no_proxy', 'all_proxy',
  'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS',
  // Only if the user already set them: we pass the PATH to the CLI's own config dir, never read it.
  'CLAUDE_CONFIG_DIR', 'CODEX_HOME',
] as const;

/** Extra names for the interactive login (terminal UI and opening a browser). */
const LOGIN_ALLOW = ['TERM', 'COLORTERM', 'DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'DBUS_SESSION_BUS_ADDRESS', 'BROWSER', 'SHELL', 'WT_SESSION'] as const;

export interface BuildEnvOptions {
  /** Directory exported as TEMP/TMP/TMPDIR (the fresh, empty working dir's parent or the dir itself). */
  tempDir: string;
  login?: boolean;
  platform?: NodeJS.Platform;
}

export function buildCliEnv(parent: NodeJS.ProcessEnv, opts: BuildEnvOptions): Record<string, string> {
  const allow = new Set<string>([...BASE_ALLOW, ...(opts.login ? LOGIN_ALLOW : [])].map((n) => n.toLowerCase()));
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(parent)) {
    if (value === undefined) continue;
    if (!allow.has(name.toLowerCase())) continue;
    out[name] = value;
  }
  const win = (opts.platform ?? process.platform) === 'win32';
  if (win) {
    out.TEMP = opts.tempDir;
    out.TMP = opts.tempDir;
    const root = Object.entries(out).find(([n]) => /^(systemroot|windir)$/i.test(n))?.[1];
    if (root) out.ComSpec = `${root}\\System32\\cmd.exe`;
  } else {
    out.TMPDIR = opts.tempDir;
  }
  return out;
}
