# Baselines

`--write-baseline <file>` accepts today's findings; `--baseline <file>` then gates only on what is not accepted.

## File format (version 2)

```json
{
  "version": 2,
  "format": "deployready-baseline/2",
  "entries": [
    {
      "fingerprint": "3f9c...20 hex chars.0",
      "rule": "hardcoded-secret",
      "file": "src/config.js",
      "severity": "critical",
      "acceptedAt": "2026-06-01",
      "reason": null,
      "owner": null,
      "expiresAt": "2026-09-01"
    }
  ]
}
```

Entries are sorted by file, rule, fingerprint with a fixed key order, so a baseline change shows up as a small, reviewable diff. `reason`, `owner` and `expiresAt` are yours to edit; `--write-baseline` on an existing file preserves them (and `acceptedAt`) for entries that still match.

## Identity

`rule + normalized path + endpoint + enclosing function/route + normalized line context + occurrence index`. The line context is the finding line with whitespace collapsed and every string literal replaced by a length class, so no secret, and no hash of a secret, is stored. Line numbers are not part of identity, so moving code is fine. Severity is not part of identity; it is stored separately.

## Gate output

- new: not in the baseline (including a second issue of the same rule in the same file)
- escalated: accepted at a lower severity, now worse (gates at the new severity)
- reopened: was recorded as resolved by a later `--write-baseline`, now back (gates until re-accepted)
- expired: the entry's `expiresAt` date has passed (gates)
- stale: entry with no matching finding; reported, and fails with `--strict-baseline`

When `--write-baseline` finds an accepted issue gone, it keeps the entry with a `resolvedAt` date so a recurrence is "reopened" rather than silently suppressed. Delete such entries by hand if you want them forgotten.

## Compatibility

v1 files (`{"fingerprints": [...]}`) still load, matching by rule+file+endpoint only and without severity checks, with a migration warning. Re-run `--write-baseline` to upgrade. `Finding.id` (used by the checklist and MCP) is unchanged.
