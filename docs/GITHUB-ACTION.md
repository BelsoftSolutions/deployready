# DeployReady GitHub Action

A composite action that runs a static DeployReady scan on your repository, writes a summary to the job page, keeps one sticky comment on pull requests, uploads SARIF to GitHub code scanning, and fails the job according to `fail-on`.

## Minimal workflow

```yaml
name: DeployReady
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # SARIF upload
  pull-requests: write     # PR comment

jobs:
  deployready:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: BelsoftSolutions/deployready@v0.5.0
```

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Project path to scan. |
| `fail-on` | `critical` | `critical`, `warning`, `info` or `none`. The job exits 2 when the gate fails. |
| `version` | `latest` | npm version of `deployready` to run (pin it for reproducible CI). |
| `comment` | `true` | Create or update one PR comment (marker `<!-- deployready -->`). |
| `sarif` | `true` | Upload SARIF to code scanning. |
| `args` | empty | Extra CLI arguments, split on spaces (for example `--baseline .deployready-baseline.json`). |

The action always runs `analyze --json --no-dynamic --no-ai`, so it needs no secrets and never touches a live app.

## Permissions

- `contents: read` to check out the code.
- `security-events: write` for the SARIF upload (set `sarif: false` to skip it). Code scanning must be available for the repository (public repos, or GitHub Advanced Security on private ones).
- `pull-requests: write` for the PR comment (set `comment: false` to skip it). Pull requests from forks get a read-only token, so the comment is skipped with a warning; the job summary still shows the result.

## What you get

- A job summary and PR comment with the score, severity counts and the top 10 findings with `file:line`.
- A `deployready-report` artifact with `deployready.json`, `deployready.sarif` and the summary.
- Code-scanning alerts. Findings without a source file (live endpoint findings) are not valid SARIF locations for GitHub, so they are left out of the SARIF and appear in the JSON report. Evidence in SARIF messages is already redacted.

## Local SARIF

```bash
npx deployready@latest analyze . --no-ai --no-dynamic --sarif deployready.sarif
```

## Pinning

The action itself references `actions/setup-node`, `actions/upload-artifact`, `actions/github-script` and `github/codeql-action/upload-sarif` by tag. Each has a TODO in `action.yml` to pin it to a full commit SHA; do that (or fork the action) if your policy requires SHA pinning.
