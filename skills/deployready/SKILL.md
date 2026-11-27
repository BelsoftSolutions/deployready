---
name: deployready
description: Scan the project for security and production-readiness issues with DeployReady, fix them, and have DeployReady verify each fix. Use before deploying or when the user asks if the app is safe or ready to ship.
---

# DeployReady: scan, fix, verify

DeployReady is a local-first scanner. You do the fixing; DeployReady finds issues and checks your work. It never sends code anywhere and has no AI of its own in this loop.

## The loop

1. **scan**: list findings and the score.
2. **apply_safe_fixes**: let DeployReady apply its deterministic, backed-up fixes first.
3. **Fix the rest yourself**: for each remaining finding (critical first), call **get_finding** (it returns the recommendation, OWASP/CWE and the whole file with the line marked), then edit the code with your own tools. Fix the cause, not the symptom.
4. **verify** each finding id after you edit. Only call it fixed when the status is `fixed`. If it is `still-present`, look again. For any other status, read `detail` and tell the user it could not be confirmed.
5. **score** at the end: report the score and the verdict. Ready means no open critical findings.

## With the MCP server (preferred)

Tools: `scan(path?, dynamic?)`, `get_finding(id)`, `apply_safe_fixes(path?)`, `verify(id)`, `score(path?)`.

Set it up once:

```bash
claude mcp add deployready -- npx -y deployready@latest mcp
```

Use `dynamic: true` only if the user's app is already running on localhost; it sends GET requests to it.

## Without MCP (CLI only)

```bash
npx -y deployready@latest analyze . --no-ai --no-dynamic --json          # scan, machine-readable
npx -y deployready@latest analyze . --no-ai --no-dynamic --fix --yes     # safe fixes, re-scan, new score
npx -y deployready@latest analyze . --no-ai --no-dynamic --json --fail-on critical   # final gate (exit 2 if criticals remain)
```

Edit the remaining findings by hand, then re-run the last command to confirm.

## Rules

- Never hide a finding by deleting the check, silencing the scanner or editing ignore files to dodge it.
- A leaked secret must be rotated, not only removed from the code. Tell the user to rotate it.
- Do not claim the app is secure. Say what was fixed, what DeployReady verified, and what is still open.
- Don't touch files outside the project. Backups from `apply_safe_fixes` are the `.bak.*` files it reports; leave them for the user to delete.
