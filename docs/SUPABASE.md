# Supabase checks

DeployReady can show what your Supabase project actually exposes. It does this without dumping your data, and it only runs live checks against a project you prove you own.

```bash
# static checks only (no network): these run on every `analyze`
deployready analyze .

# live, read-only checks against your own project
export SUPABASE_URL=https://<ref>.supabase.co
export SUPABASE_ANON_KEY=...            # public anon / publishable key
export SUPABASE_SERVICE_ROLE_KEY=...    # proof of ownership (or SUPABASE_ACCESS_TOKEN)
deployready analyze . --supabase

# local project from `supabase start` (no ownership proof needed)
SUPABASE_URL=http://127.0.0.1:54321 SUPABASE_ANON_KEY=... deployready analyze . --supabase
```

MCP: the `supabase_check` tool takes `path`, `live` and `crossUser`. It reads credentials from the server's environment only, never from tool arguments, and goes through the same ownership gate.

## Checks

### Static (always on, no network)

| Rule | Severity | What it means |
| --- | --- | --- |
| `supabase-service-jwt-client` | critical | A key literal in client-side code decodes to `role: service_role` (or is an `sb_secret_…` key). Client-side code means a `"use client"` file, or `src/`, `app/` or `components/` in a Vite app; API routes, `server/`, `supabase/functions` and `*.server.*` files are excluded. |
| `supabase-service-jwt-public-env` | critical | A public env var (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `NUXT_PUBLIC_`, `PUBLIC_`, `GATSBY_`) holds a service-role value, whatever the variable is called. |

This module decodes key values. Name-based detection (the string `service_role`, secret-named public variables) is handled by the general `supabase-service-role` rule. The static pass also finds the project URL, the anon key (it must belong to the same project ref) and the tables in your SQL migrations, for use by the live checks.

### Row-Level Security in your migrations (static, always on)

DeployReady replays your SQL in migration order and judges only the final state. Files under a `migrations/` directory (such as `supabase/migrations/<timestamp>_*.sql` or Prisma's numbered folders) run first, in natural filename order. Every other `.sql` file runs after them. While replaying, it tracks:

- tables: `CREATE` (including `UNLOGGED`, `PARTITION BY` and `PARTITION OF`; `TEMP` tables are skipped), `DROP`, `RENAME`, `SET SCHEMA`, `ALTER SCHEMA ... RENAME`, columns, schema-qualified and `"Quoted"` names, and `SET search_path`
- RLS: `ENABLE`, `DISABLE`, `FORCE` and `NO FORCE ROW LEVEL SECURITY`
- policies: `CREATE`, `ALTER` (including `RENAME`) and `DROP POLICY`, permissive or restrictive, the command, the roles, `USING` and `WITH CHECK`
- privileges: Supabase's default grants on `public`, `GRANT` and `REVOKE` (including `ALL TABLES IN SCHEMA`), and `ALTER DEFAULT PRIVILEGES`
- `DO` blocks: plain statements inside them, such as `if not exists (...) then create policy ...`, and `execute '<literal>'` are applied

A policy that was dropped, a table that was renamed or moved, and RLS that was disabled and then re-enabled are all judged as they end up.

| Rule | Severity | What it means |
| --- | --- | --- |
| `rls-not-enabled` | critical on sensitive tables, otherwise warning | An API-exposed table ends up without RLS. This covers tables that were never enabled, re-created after a `DROP`, renamed or moved into `public`, unlogged tables, partitions of a protected parent, and a same-named table in another schema or with different quoting. It only fires when the project is clearly Supabase or enables RLS somewhere else. |
| `rls-disabled` | critical | The final word on an exposed table is `DISABLE ROW LEVEL SECURITY`. A disable that a later migration reverts is not reported. |
| `rls-permissive-policy` | critical, warning, or not reported (see below) | A permissive policy is true for every row for `anon` or for any signed-in user, a restrictive policy does not narrow it, and the role holds the table privilege. |
| `rls-no-policy` | info | RLS is on but no policy remains. Every request is denied. |

An expression counts as true for every row when it folds to TRUE for that role. Examples: `true`, `1 = 1`, `'a' = 'a'`, `true and true`, `not false`, `x or true`, `col = col`, `'t'::boolean`. Checks such as `auth.role() = 'authenticated'`, `auth.uid() is not null`, `auth.jwt() ->> 'role' = 'authenticated'` and `current_user = 'authenticated'` are true for any signed-in user, so they verify a role, not ownership. One more case is covered: a membership subquery whose join compares a column with itself (`exists (select 1 from members m where ... and m.org_id = org_id)`, where the unqualified `org_id` resolves to `m.org_id`). Anything the scanner cannot evaluate, such as owner checks, helper functions or unparseable expressions, is treated as restrictive, so it never produces a finding.

**Data sensitivity** sets the severity of an open read:

- **Sensitive tables** are critical. A table is sensitive if `sensitiveTables` lists it, if its name suggests private data (invoices, payments, transactions, orders, messages, profiles, users, roles, auth, secrets, customers, documents, and so on), or if it has a per-user or per-tenant column (`user_id`, `owner_id`, `org_id`, `tenant_id`, `team_id`, `workspace_id`, and so on, plus `tenantColumns`).
- **Unknown tables** get a warning: "review required: is public read intended?".
- **Public tables** get no finding. A table is public if `publicTables` lists it, if it is catalog data (products, categories, tags, ...), or if it is content with a publish flag (posts or articles with `published`, `is_public`, `status`, ...).

Open writes are critical on sensitive tables and a warning everywhere else.

**Exposed schemas.** Only schemas served by the Data API matter for `anon` and `authenticated`. The default is `public` (and `graphql_public`). If `supabase/config.toml` sets `[api] schemas = [...]`, that list is used instead. `exposedSchemas` in the project config overrides both.

**Project config.** Put a `.deployready.json` in the project root, or the same object under a `"deployready"` key in `package.json`:

```json
{
  "publicTables": ["announcements", "public.changelog"],
  "sensitiveTables": ["widgets"],
  "tenantColumns": ["shop_id"],
  "exposedSchemas": ["public", "api"]
}
```

**Parser choice.** `pgsql-ast-parser` (MIT, pure JS) was rejected because it cannot parse `CREATE POLICY`, `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`, `GRANT` or `PARTITION BY`. `libpg-query` (MIT, the real Postgres grammar compiled to WASM, about 1.8 MB, no native build) parses all of them. It is not used at runtime, for three reasons: it would add a large dependency with a single maintainer to every install; it is asynchronous; and one bad statement fails the whole file. Instead, `src/analysis/postgres/` uses a small, tolerant statement-level parser that skips what it does not understand. It was cross-checked against libpg-query on every SQL file in `benchmark/corpus/rls` plus a pg_dump-style file: all 72 policies agree on table, command, roles, permissive/restrictive and clause presence.

**Ground truth.** `benchmark/corpus/rls` contains 38 labelled cases: 16 reconstruct an external audit (10 insecure, 6 secure), and 22 are variations. Every label was confirmed against PostgreSQL 16 with `benchmark/rlsPgProof.ts`. That script applies the migrations to a Supabase-like database (anon, authenticated and service_role roles, default grants, `auth.uid()` and `auth.role()`) and reads or writes another user's rows as `anon` and as a signed-in user.

**Not covered yet:** storage policies, `SECURITY DEFINER` functions and `search_path` hijacking, views (and `security_invoker`), triggers, Realtime, column-level grants as a restriction, and drift between your migrations and the live database. Use `--supabase` for the live checks.

### Live (`--supabase`, ownership-gated, read-only)

| Rule | Severity | How it is proven |
| --- | --- | --- |
| `supabase-anon-read` | critical | `HEAD /rest/v1/<table>?select=*&limit=1` with `Prefer: count=exact` and the anon key. If the `Content-Range` total is above 0, the table is exposed. The evidence is the count ("anon can read 7 of 7 rows"; the total comes from the same request made with the service key) plus at most 10 column names, taken from the schema, never from rows. |
| `supabase-rpc-anon-executable` | warning | The function appears in the anon role's own PostgREST OpenAPI document, which means anon has EXECUTE. **No function is invoked.** |
| `supabase-storage-public-bucket` | warning | `GET /storage/v1/bucket` (service key, or anon if none) reports `public: true`. |
| `supabase-storage-anon-list` | critical | `POST /storage/v1/object/list/<bucket>` with the anon key and `limit: 1` returns an object. Object names are not reported. |
| `supabase-open-signups` | info | `GET /auth/v1/settings` reports `disable_signup: false`. |
| `supabase-email-confirm-off` | info | `GET /auth/v1/settings` reports `mailer_autoconfirm: true`. |
| `supabase-cross-user-read` | critical | Opt-in with `--supabase-cross-user`. Signs in two test users and, for each table with an owner column (`user_id`, `owner_id`, `created_by`, …, or `id` on `profiles`/`users`), counts rows where owner = B, first as B (the control) and then as A. If A's count is above 0, user A can read user B's rows. |

Tables come from the PostgREST OpenAPI root, read with the service key, or with the anon key if that is all there is. If neither works, they come from the `CREATE TABLE` statements in your local migrations. The live checks probe at most 50 tables, 20 RPC functions and 20 buckets.

Every live finding carries `proof`: a reproducible `curl` command, the status, the `Content-Range`, and a control where one exists. Keys appear only as `${SUPABASE_ANON_KEY}` / `${USER_A_ACCESS_TOKEN}` placeholders, and the whole proof passes through `redact()`.

**Writes are not implemented.** No insert, update or delete test is ever sent, so this release does not prove write exposure. Treat a readable table as also possibly writable until you have checked its INSERT, UPDATE and DELETE policies.

## Credentials

| Mode | Needed | Ownership proof |
| --- | --- | --- |
| Local (`supabase start`) | `SUPABASE_URL` (loopback, e.g. `http://127.0.0.1:54321`) + `SUPABASE_ANON_KEY` | Not needed: a loopback URL is your machine. `SUPABASE_SERVICE_ROLE_KEY` is optional; it adds totals and storage bucket metadata. |
| Hosted, service key | `SUPABASE_URL` + `SUPABASE_ANON_KEY` + `SUPABASE_SERVICE_ROLE_KEY` | The key must be a service_role / `sb_secret_` key. Its `ref` claim, if present, must match the URL. `GET /auth/v1/admin/users?per_page=1` must return 200; the response body is discarded unread. |
| Hosted, access token | `SUPABASE_URL` + `SUPABASE_ANON_KEY` + `SUPABASE_ACCESS_TOKEN` | `GET https://api.supabase.com/v1/projects` must list the URL's project ref. Requires a `<ref>.supabase.co` URL; custom domains need the service key. Without a service key, tables come from the anon OpenAPI document or from your migrations. |
| Cross-user (opt-in) | Add `SUPABASE_TEST_USER_A_EMAIL`, `SUPABASE_TEST_USER_A_PASSWORD`, `SUPABASE_TEST_USER_B_EMAIL`, `SUPABASE_TEST_USER_B_PASSWORD` | Two test accounts you created. User B should own at least one row in the tables under test. |

Flags (`--supabase-url`, `--supabase-anon-key`, `--supabase-service-key`, `--supabase-access-token`) override env vars. Env vars override values found in the project files. Prefer env vars for secrets, because flags end up in shell history. Secrets are never printed, and the URL and anon key are the only values ever taken from project files.

## Safety guarantees

- **Ownership gate.** The anon key is public, so holding it proves nothing. Without a loopback URL or a validated service key or access token for *that* project, the run is refused before any data-plane request is sent. This keeps DeployReady from becoming a scanner for other people's apps.
- **Read-only, counts only.** Table probes are `HEAD` with `limit=1`, so no row content is transferred. The only POSTs are the password sign-in for the opt-in test users and a storage `list` with `limit: 1`.
- **One client.** All traffic goes through `src/supabase/http.ts`. It is bound to one origin, uses https only (http is allowed for loopback), keeps at least 250 ms between requests, has a 300-request budget, a 10 s timeout, no redirects and a 5 MB response cap.
- **Consent.** Interactive runs ask before the live checks start; `--yes` skips the question. The MCP tool runs live checks only when called with `live: true`.

## Test against your own project (still needs real-project validation)

The module is unit-tested against a mocked transport only. Before you rely on it, run it once against a throwaway project you own and confirm each item:

- [ ] `GET /auth/v1/admin/users?page=1&per_page=1` returns 200 with the service key and 401/403 with the anon key, for both legacy JWT keys and the new `sb_secret_` keys.
- [ ] `GET https://api.supabase.com/v1/projects` with a personal access token returns an array whose items have `id` = project ref.
- [ ] `GET /rest/v1/` with `Accept: application/openapi+json` returns the Swagger 2 document for the service key. Check what it returns for the anon key: newer projects may restrict it, and if they do, the RPC check reports "could not determine".
- [ ] `HEAD /rest/v1/<table>?select=*&limit=1` with `Prefer: count=exact` returns a `Content-Range: 0-0/N` header (or `*/0`) through the Supabase gateway. Expected results: RLS off gives N > 0; RLS on with no policy gives 0.
- [ ] The anon OpenAPI document lists only functions anon may EXECUTE (test with `REVOKE EXECUTE ... FROM anon, public`).
- [ ] `GET /storage/v1/bucket` lists buckets with `public`, and `POST /storage/v1/object/list/<bucket>` with the anon key returns `[]` when no SELECT policy exists on `storage.objects`.
- [ ] `GET /auth/v1/settings` exposes `disable_signup` and `mailer_autoconfirm`.
- [ ] `POST /auth/v1/token?grant_type=password` returns `access_token` and `user.id` for the test users, and the A-reads-B count matches what your policies allow.
- [ ] Rate limiting: a scan of about 50 tables stays well under the project's API rate limits at a 250 ms spacing.
