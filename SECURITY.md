# Security policy

## Reporting a vulnerability in DeployReady

Please report security issues privately, not in public issues.

Use GitHub private vulnerability reporting: open the repository's **Security** tab, choose **Report a vulnerability** (or go to <https://github.com/BelsoftSolutions/deployready/security/advisories/new>). If you cannot use GitHub, open a public issue that says only that you need a private contact channel, without details.

<!-- TODO(maintainers): add a security contact email here if one is set up. -->

Include the version (`deployready --version`), what you did, and what you expected. Reports about the tool itself are in scope: for example secret leakage in output or AI payloads, scanning or probing outside the intended target, path traversal out of the project root, or unsafe handling of AI/CLI provider output. Findings that DeployReady reports about *your* project are not vulnerabilities in DeployReady.

## Supported versions

| Version | Supported |
|---|---|
| 0.6.x | yes |
| 0.5.x | security fixes until 0.7.0 |
| 0.4.x | no, please upgrade: 0.5.0 fixes secret-redaction and CI-baseline issues found in 0.4.x |
| < 0.4 | no, please upgrade |

## What leaves your machine

- Scanning, scoring, reports, fixes and the MCP server run locally. The MCP server never calls an AI model itself.
- AI analysis is optional and off with `--no-ai`. When enabled and after you approve, only a redacted, structured findings report is sent to the provider you chose (Claude API, OpenAI API, or your own `claude`/`codex` CLI login). For `fix`, one redacted snippet that you confirm first may be sent. Source files are not sent. With Ollama, nothing leaves your machine.
- Live checks only contact the target you point them at (see below). Supabase live checks contact your Supabase project, and, with an access token, `api.supabase.com` to prove ownership.
- API keys are read from environment variables first and are not logged; the on-disk config (`~/.deployready/config.json`) is written with `0600` permissions. All terminal output and AI payloads pass through a secret redactor, which is pattern-based and not a guarantee.

## Safety model of live tests

- **Dynamic tests** target a server on loopback and are GET-only by default. Only routes your code or OpenAPI file defines (plus a bounded set of links your app advertises) are requested; aggressive tests need explicit consent.
- **Active tests** (`--active`) need your token and run against loopback. A non-loopback host is allowed only if you name that exact host with `--i-own-this-target` (no wildcards or subdomains). The tampering checks are GET-only. The unauthenticated write-route probe stays loopback-only, targets ids that cannot exist, skips `PUT`, and sends no body.
- **Supabase tests** (`--supabase`) are read-only: no insert, update or delete is ever sent, and no RPC function is invoked. Against a hosted project they run only after you prove ownership with the service-role key or an access token; a loopback URL (`supabase start`) needs no proof. Details: [docs/SUPABASE.md](docs/SUPABASE.md).
- **Common-path probe** is opt-in, at most 20 GET requests to a printed fixed list.

Only run active or Supabase tests against systems you own or are authorized to test.
