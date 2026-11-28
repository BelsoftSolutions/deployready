# Authorization matrix (policy-driven active testing)

Since 0.6, `deployready analyze --active` can test your app against an explicit authorization policy: for each resource, each identity and each action it decides what *should* happen, sends the requests, and reports what *did* happen. It is the 0.5 active engine (field-level verdicts, safety levels, request budget, redacted proofs) driven by a policy instead of two tokens.

The matrix runs when the project's `.deployready.json` has an `active.policy` (or `active.identities`). Without one, `--active --token ... --token-b ...` keeps the token-based scan described in the README.

## 1. Draft a policy

```bash
npx deployready policy init .            # writes active.policy (+ example identities) into .deployready.json
npx deployready policy init . --print    # print the draft instead
npx deployready policy init . --force    # replace an existing policy
```

The draft is built from the discovered routes with simple heuristics, and is marked `"draft": true` with a `_comment` saying so:

| Route looks like | Drafted access |
| --- | --- |
| contains `/admin`, `/internal`, `/staff`, ... | `anonymous: none, user: none, admin: manage` |
| `/users/:id`, `/accounts`, `/profile`, `/me` | `anonymous: none, user: own, admin: manage` |
| public catalog (`/products`, `/posts`, `/categories`, `/pricing`, ...) | `anonymous: read, user: read, admin: manage`, `tenantScoped: false` |
| any other record | `anonymous: none, user: own, admin: manage` |
| `/batch`, `/bulk`; `.../export`, `.csv` | kept with `"sideEffectFree": false` (not requested until you set it to `true`) |
| login, logout, auth callbacks, webhooks, health | excluded (listed under `_excluded`) |
| `/graphql` | `graphql: { endpoint, introspection: "deny" }` |

**DeployReady refuses to test a draft.** Review every resource, fix the levels, then set `"draft": false`.

## 2. Identities

```json
{
  "active": {
    "identities": [
      { "name": "anonymous", "role": "anonymous" },
      { "name": "alice", "role": "user", "tenant": "acme", "tokenEnv": "DR_ALICE_TOKEN",
        "params": { "userId": "u_alice", "org": "acme" },
        "objects": { "invoices": { "id": "inv_a" }, "projects": { "id": "p_acme" } } },
      { "name": "bob", "role": "user", "tenant": "acme", "session": "bob" },
      { "name": "admin", "role": "admin", "tokenEnv": "DR_ADMIN_TOKEN" },
      { "name": "other-tenant", "role": "user", "tenant": "globex", "tokenEnv": "DR_EVE_TOKEN",
        "objects": { "invoices": { "id": "inv_e" } } }
    ]
  }
}
```

- Credential, one of: `tokenEnv` (an environment variable holding a bearer token; the name must contain `TOKEN`, `JWT`, `SESSION`, `COOKIE` or `AUTH`, so a shared config cannot make the scanner read an unrelated secret), `token` (a literal bearer token; avoid it in a committed file), or `session` (a session saved by `deployready auth record <name>` / `deployready auth login`; its cookies and bearer token are sent only to the scan target). Only the `anonymous` role may have none. An anonymous identity is always added.
- `params` (route parameter → value, for every route) and `objects` (resource name → parameter → value) name the identity's **own** records. Use `objects` for record ids. User-ish parameters (`userId`, `/users/:id`) and tenant-ish parameters (`org`, `tenantId`) fall back to `tenant` and to JWT claims (`sub`, `org_id`). Nothing is ever guessed: a route whose parameters no identity declares is `untested`.
- `--token` / `--token-b` are added as identities `token` and `token-b` (role `user`).
- An identity that cannot be built (variable unset, session missing or expired) stays in the matrix with its cells `untested` and the reason.

Session providers other than the built-in Playwright one can be plugged in with `registerSessionProvider(kind, factory)` (`src/active/identities.ts`); an identity selects one with `"session": { "provider": "<kind>", ... }`. Every provider implements:

```ts
interface IdentityProvider { name: string; role: string; tenant?: string; headers(): Promise<Record<string, string>> }
```

## 3. Policy

```json
{
  "active": {
    "policy": {
      "draft": false,
      "resources": [
        { "name": "invoices",
          "routes": ["GET /api/invoices", "GET /api/invoices/:id", "PATCH /api/invoices/:id", "DELETE /api/invoices/:id",
                     "POST /api/invoices", "GET /api/invoices/:id/download", "GET /api/user-invoices?userId=:userId",
                     { "route": "POST /api/invoices/batch-get", "batchField": "ids", "sideEffectFree": true }],
          "access": { "anonymous": "none", "user": "own", "admin": "manage" },
          "tenantScoped": true,
          "body": { "title": "DeployReady test invoice" } },
        { "name": "admin-stats", "routes": ["GET /admin/stats"], "access": { "user": "none", "admin": "manage" } }
      ],
      "graphql": { "endpoint": "/graphql", "introspection": "deny",
                   "queries": [{ "resource": "invoices", "query": "query($id: ID!) { invoice(id: $id) { id total } }", "variable": "id" }] }
    }
  }
}
```

| Level | Read | Change |
| --- | --- | --- |
| `none` | nothing (not even the route) | nothing |
| `read` | every record | nothing |
| `own` | own records only | own records only |
| `manage` | every record | every record |

`tenantScoped` (default `true`): no level reaches a record of another tenant, except for an identity without a `tenant` (platform-wide). A role missing from `access` is `none` (`"*"` sets a default). Routes accept `:param`, `{param}` and `[param]`, and query bindings (`?userId=:userId`). GraphQL `queries` must be queries; a mutation or subscription is rejected.

## 4. What is tested

| Test | How | Rule |
| --- | --- | --- |
| Missing server-side authorization | anonymous requests a route/record the policy does not open to anonymous | `authz-missing-auth` |
| Vertical (BFLA) | a role requests a route reserved for other roles; compared with an allowed identity's answer | `authz-bfla` |
| Horizontal (BOLA/IDOR) | user A requests user B's record (path, query parameter, GraphQL id) | `authz-bola` |
| Cross-tenant | a record of another tenant | `authz-cross-tenant` |
| Nested ids | A's own parent id + B's child id: `/orgs/<A's org>/projects/<B's project>` | `authz-cross-tenant` / `authz-bola` |
| List filtering | A's list route must not contain B's records | `authz-bola` / `authz-cross-tenant` |
| Batch | an `ids` array with A's and B's ids | `authz-bola` / `authz-cross-tenant` |
| Export / download | as above, on export routes (read requests only) | as above |
| GraphQL introspection | anonymous `__schema` query | `graphql-introspection` (warning) |
| Cross-identity write *(stateful)* | A changes a text field of B's record; B reads it back | `authz-unauthorized-write` |
| Cross-identity delete *(stateful)* | B creates a fresh record (resource `body`), A deletes it, B reads it back | `authz-unauthorized-write` |
| Mass assignment *(stateful)* | extra `ownerId` / `tenantId` / `price` / `amount` / `verified` fields on create or update of the identity's own record, read back; a create is compared with a control create without them | `authz-mass-assignment` |
| Privilege escalation via role fields *(stateful)* | `role` / `isAdmin` / `permissions` on the identity's own record, read back | `authz-privilege-escalation` |

Only fields that already exist on the record are tried, and a value counts only when the read-back shows the client's value where the record had a different one.

## 5. Verdicts

Every cell of (resource route, identity, record owner) gets one:

- **allowed-as-expected** / **denied-as-expected**: the app did what the policy says. A denial means the owner's (or an allowed identity's) private values are absent from the answer while that identity can read them, or an explicit 401/403.
- **VIOLATION**: proven. For reads, the owner's private values appear in the answer (field-level, any status code; an echo of the id is not enough; volatile fields are learned from repeated baselines; an anonymous control tells a public record from a leak). For writes, the read-back shows the change. Each violation carries a plain-English statement (*User "alice" (role user, tenant acme) could read invoices of "bob"*) and becomes a finding with a redacted proof: a `curl` command whose credential is the placeholder `$ALICE_AUTH`, the status, the response with the owner's values masked, and the control.
- **inconclusive**: neither proven safe nor proven vulnerable (for example an SPA fallback page, a suspected leak with one non-sensitive value, a refusal of a request the policy allows).
- **untested**: could not run, with the reason (safety level, `unsafeRoutes`, missing ids, unavailable identity, budget).

Violations of one rule on one route are grouped into one finding. The matrix (cells, identities, summary, routes the policy does not cover) is in `--json` (`authz`), the markdown report and the HTML dashboard.

## 6. Safety

- The same gates as every active scan: opt-in (`--active`), a confirmation prompt (unless `--yes`), loopback only unless you name an owned host (`--i-own-this-target`, or `ownedTargets` in your **user** config; the project file cannot add hosts), a hard request budget (`active.maxRequests`, default 200).
- `read-only` (default) sends GET requests, plus POST only for GraphQL queries and batch routes you declared `sideEffectFree`. Side-effect-looking GET paths (export, logout, ...) and `unsafeRoutes` are skipped unless declared `sideEffectFree`; an `unsafeRoutes` route is never used as a read-back either.
- Anything that writes needs `--safety-level stateful`, which is refused unless the config declares `"disposableEnvironment": true` **and** the target is loopback or an owned host. Writes run after all reads; changed fields are restored where the owner may do so.
- `--dry-run` (or `passive`) prints the matrix plan (each cell, the expected outcome, an upper bound of requests) and sends nothing; saved sessions are not even loaded.
- Credentials are never written to a report; response bodies are masked and redacted.

## 7. Re-checking a finding

`verify` (interactive shell / MCP) re-runs the matrix for the finding's route with the same `.deployready.json` identities (credentials from the environment and saved sessions): `still-present` with a fresh proof, `fixed` when the cells are denied as expected, otherwise `inconclusive` and why.
