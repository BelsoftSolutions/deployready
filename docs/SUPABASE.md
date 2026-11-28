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

**Not covered yet:** policies that call your own helper functions are treated as restrictive; overloaded functions are tracked by name, not signature; dynamic SQL (`execute format(...)`) inside function bodies is not followed; `DO` blocks only apply DDL and grants. Use `--supabase` for the live checks and `--supabase-db-url` for drift.

### Storage, functions, views, triggers, Realtime and grants (static, always on)

The same replay also tracks `storage.buckets` rows (`INSERT ... VALUES`, `ON CONFLICT DO NOTHING / DO UPDATE SET public = ...`, `UPDATE ... SET public`, `DELETE`), policies on `storage.objects`, functions (`CREATE [OR REPLACE] FUNCTION`, `ALTER FUNCTION ... SECURITY DEFINER | SET search_path | RENAME | SET SCHEMA`, `DROP FUNCTION`, `GRANT / REVOKE EXECUTE`, including `ALL FUNCTIONS IN SCHEMA` and default privileges `ON FUNCTIONS`), views and materialized views (`WITH (security_invoker = ...)`, `ALTER VIEW ... SET / RESET`, the tables they read), triggers (`CREATE TRIGGER ... EXECUTE FUNCTION`, moving with the table), the `supabase_realtime` publication (`CREATE / ALTER PUBLICATION ... ADD / DROP / SET TABLE`, `FOR ALL TABLES`, `TABLES IN SCHEMA`) and column-level grants (`GRANT SELECT (a, b) ON t`). Two Postgres facts the model follows, both checked on PostgreSQL 16: new functions are executable by `PUBLIC`, and Supabase also grants `EXECUTE` to `anon` and `authenticated` in `public`, so `REVOKE ... FROM PUBLIC` alone still leaves `anon` able to call it; and `CREATE OR REPLACE VIEW` without a `WITH (...)` clause drops `security_invoker`.

These checks run when the project is clearly Supabase or uses RLS. Severity follows data sensitivity, as for RLS (table names and columns, bucket names, `.deployready.json`).

| Rule | Severity | What it means |
| --- | --- | --- |
| `storage-bucket-public` | critical when the bucket name looks private (invoices, documents, kyc, receipts, uploads, ...), warning when unknown, not reported for public assets (avatars, images, media, ...) | The bucket ends up `public = true`: anyone with a file path downloads it from `/storage/v1/object/public/<bucket>/...`; no `storage.objects` policy is checked. |
| `storage-policy-permissive` | critical for reads of a private-looking bucket and for anon writes, warning otherwise | A `storage.objects` policy is true for every file of a bucket for `anon` or any signed-in user: it checks `bucket_id = 'x'` (or a role) but never the owner (`owner_id = auth.uid()`, `(storage.foldername(name))[1] = auth.uid()::text`). Each bucket in an `OR` is judged separately; a restrictive policy that narrows it closes the gap. |
| `security-definer-rls-bypass` | critical on sensitive tables, warning on unknown ones | A `SECURITY DEFINER` function in an exposed schema that `anon` or `authenticated` may execute reads or writes an RLS-protected table and never looks at the caller (`auth.uid()`, `auth.jwt()`, `auth.role()`, `current_user`). It runs as its owner, so `POST /rest/v1/rpc/<fn>` returns other users' rows. |
| `security-definer-exposed` | warning when anon may call it and the body never checks the caller, otherwise info | Any other `SECURITY DEFINER` function callable through the API. |
| `security-definer-search-path` | warning (CWE-426) | A `SECURITY DEFINER` function without `SET search_path` in a project schema (Supabase-owned schemas are skipped). Names in its body resolve through the caller's path; a caller's temporary table shadows yours. |
| `view-rls-bypass` | critical on sensitive tables, warning on unknown ones | A view in an exposed schema, readable by anon or authenticated, over an RLS-protected table, without `security_invoker = true` (PG15+) and without a caller filter in its query; or a materialized view there. Views run as their owner, so RLS does not apply. |
| `trigger-privilege-escalation` | critical (CWE-269) | A `SECURITY DEFINER` trigger function writes a role / admin table (or role-like columns) from caller-controlled input: `new.raw_user_meta_data` on `auth.users` (set by whoever signs up), or `new.role` / `new.is_admin` / ... on a table the caller can insert or update. `new.raw_app_meta_data` and fixed values are fine. |
| `realtime-table-exposed` | critical on sensitive tables, warning on unknown ones | A table in `supabase_realtime` has no RLS or an always-true SELECT policy, so every change is pushed to any subscriber. |
| `grant-default-privileges-anon` | warning for every schema (no `IN SCHEMA`) or an exposed one, info for a private schema | `ALTER DEFAULT PRIVILEGES ... GRANT` write privileges on tables (or `EXECUTE` on functions) to `anon` / `PUBLIC`. Restating Supabase's own defaults in `public` is not reported. |
| `grant-all-tables-anon` | warning | `GRANT ... ON ALL TABLES IN SCHEMA ... TO anon` re-opens tables that an earlier `REVOKE ... FROM anon` had locked down. |
| `grant-sensitive-column` | critical for credentials (password_hash, api_key, token, ...) or any anon read, warning for personal data (email, phone, ...) read by authenticated | A column-level `GRANT SELECT` includes a sensitive column and the role can read every row (no RLS, or an always-true SELECT policy). Column grants that leave such columns out are how Supabase projects hide them, and are not reported. |

Bucket config keys: `"publicBuckets": ["avatars"]`, `"sensitiveBuckets": ["exports"]` in `.deployready.json`.

### Edge Functions (static, always on)

| Rule | Severity | What it means |
| --- | --- | --- |
| `edge-function-no-auth` | critical when the function uses the service-role key, warning when it only reads or writes data with the anon key | `supabase/config.toml` sets `[functions.<name>] verify_jwt = false` and the code (`supabase/functions/<name>/index.ts`, or `entrypoint`, plus files it imports by relative path) never authenticates the request. Accepted as authentication: `auth.getUser()` / `getClaims()`, `jwtVerify` / `jwt.verify`, helpers such as `requireUser(req)`, webhook signature checks (`stripe.webhooks.constructEvent[Async]`, `new Webhook(...)`, `crypto.subtle.verify`, HMAC, known signature headers), and a header compared with a secret env var. An anon-key client that forwards the caller's `Authorization` header stays under RLS and is not reported. |

Coverage: `supabase (static)` is `passed` when the replay and these checks ran, and says how many `verify_jwt = false` functions were read (and which ones had no code in the project); it is `failed` when the object checks or the Edge Function check crash.

**Ground truth.** `benchmark/corpus/supabase-deep` holds 23 cases, a vulnerable and a safe twin for each area (20 SQL cases, 3 Edge Function cases). Every SQL label was confirmed against PostgreSQL 16 with `benchmark/supabaseDeepPgProof.ts` (the `rlsPgProof.ts` method plus `storage.buckets`, `storage.objects` with RLS, `storage.foldername()`, `auth.users.raw_user_meta_data` and a `supabase_realtime` publication): anon reads every invoice through the view and the RPC, a user reads and deletes another user's documents, a signed-up user with `{"role": "admin"}` metadata ends up admin, a temporary table shadows the table a definer function reads, and so on; each safe twin is denied.

### Drift (`--supabase-db-url`, opt-in, read-only)

```bash
deployready analyze . --supabase-db-url "postgres://readonly_user:...@db.<ref>.supabase.co:5432/postgres"
# or take it from the environment
SUPABASE_DB_URL=postgres://... deployready analyze . --supabase-db-url
```

Use a connection string you own; a read-only role is best. Setting `SUPABASE_DB_URL` alone never connects: the flag is the opt-in. DeployReady replays your migrations, reads the live catalog and reports where they differ. The session starts with `default_transaction_read_only=on` (verified with `SHOW` before any query), every query runs inside `BEGIN READ ONLY ... ROLLBACK`, and only catalog data is read: `pg_class` (`relrowsecurity`, `relforcerowsecurity`, view `reloptions`), `pg_policies`, `information_schema.role_table_grants`, `pg_proc` (`prosecdef`, `proconfig`, `has_function_privilege`), `pg_publication_tables` and `storage.buckets` (id and `public` only). No application row is selected. The password is masked in every message and finding. Driver: [`pg`](https://www.npmjs.com/package/pg) 8.23.1 (MIT, pinned; its dependencies are MIT / ISC), loaded only when drift runs.

| Rule | Severity | What it means |
| --- | --- | --- |
| `drift-rls-disabled` | critical | RLS is enabled in the migrations but disabled in the database. |
| `drift-table-unmanaged` | critical / warning by sensitivity | An exposed table exists only in the database and has no RLS. |
| `drift-policy-added` | critical / warning by sensitivity when it is always true and RLS is on, otherwise info | A policy exists only in the database. Its `qual` / `with_check` text is re-parsed with the same evaluator as the static checks. |
| `drift-policy-changed` | by sensitivity when the live version opens every row, otherwise warning | Same name, but permissive/restrictive or command differ, or the live clause is always true while the migration's is not. |
| `drift-policy-missing` | warning for a restrictive policy, info for a permissive one | A policy from the migrations is missing in the database. |
| `drift-grant-added` | warning | anon / authenticated hold a table privilege the migrations revoked. |
| `drift-function-definer`, `drift-function-search-path`, `drift-function-execute`, `drift-function-unmanaged` | critical / warning | A function became `SECURITY DEFINER`, lost its `search_path`, became executable by anon / authenticated against the migrations, or is a definer function callable through the API that no migration defines. |
| `drift-view-invoker` | by sensitivity of the view's tables | The migrations create the view with `security_invoker = true`; the database view does not have it. |
| `drift-realtime-added` | critical when the table has no RLS, otherwise warning | A sensitive table is in the live `supabase_realtime` publication but not in the migrations. |
| `drift-bucket-public` | by bucket sensitivity | A bucket is public in the database but not in the migrations. |

Coverage: a separate `supabase (drift)` area. `passed` when the catalog was read and compared, `failed` when the connection or a query failed (the reason is shown, password masked), `untested` when it was not requested, declined, or had no connection string or no migrations. Tested against PostgreSQL 16 (`DEPLOYREADY_TEST_PG_URL=postgres://postgres@127.0.0.1:<port>/postgres npx jest tests/supabase-deep.test.ts`): the migrations are applied, the database is mutated (RLS disabled, a `using (true)` policy added, `security_invoker` reset, a bucket made public) and each drift is reported, and a write through the drift session is refused.

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
