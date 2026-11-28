## DEVELOPMENT corpus (used while building rules; optimistic by construction)

108 cases, 65 positive labels, 0 negative cases.

| Tool | TP | FP | TN | FN | Precision | Recall | F1 | Sev-weighted recall | Precision incl. extras | Extra | Other | Inconclusive | Neg. cases clean | Scan time total / mean / max (s) | Peak RSS mean / max (MB) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| deployready | 65 | 0 | 96 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 0.98 | 1 | 0 | 0 | - | 41.1 / 0.38 / 0.5 | 102 / 112 |

### Per rule (TP/FP/FN; TN omitted)

| Rule | Labels | deployready |
|---|---|---|
| command-injection | 0 | 0/0/0 |
| cors-wildcard | 1 | 1/0/0 |
| debug-enabled | 0 | 0/0/0 |
| env-not-ignored | 3 | 3/0/0 |
| eval-usage | 1 | 1/0/0 |
| firebase-rtdb-auth-only | 1 | 1/0/0 |
| firebase-rtdb-open | 1 | 1/0/0 |
| firebase-rules-auth-only | 1 | 1/0/0 |
| firebase-rules-open | 2 | 2/0/0 |
| firebase-rules-open-read | 1 | 1/0/0 |
| firebase-rules-recursive-wildcard | 1 | 1/0/0 |
| firebase-rules-test-mode | 1 | 1/0/0 |
| firebase-service-account-committed | 1 | 1/0/0 |
| flask-hardcoded-secret-key | 1 | 1/0/0 |
| hardcoded-secret | 2 | 2/0/0 |
| idor-missing-ownership-check | 6 | 6/0/0 |
| insecure-cookie | 0 | 0/0/0 |
| insecure-http-url | 0 | 0/0/0 |
| insecure-random | 0 | 0/0/0 |
| jwt-hardcoded-secret | 1 | 1/0/0 |
| jwt-none-alg | 0 | 0/0/0 |
| log-injection | 0 | 0/0/0 |
| missing-auth-route | 2 | 2/0/0 |
| next-public-secret | 1 | 1/0/0 |
| possible-hardcoded-secret | 0 | 0/0/0 |
| py-flask-debug | 1 | 1/0/0 |
| py-requests-noverify | 1 | 1/0/0 |
| py-sql-fstring | 3 | 3/0/0 |
| rls-disabled | 1 | 1/0/0 |
| rls-no-policy | 0 | 0/0/0 |
| rls-not-enabled | 10 | 10/0/0 |
| rls-permissive-policy | 14 | 14/0/0 |
| sql-injection | 6 | 6/0/0 |
| supabase-service-role | 1 | 1/0/0 |
| tls-verification-disabled | 1 | 1/0/0 |
| weak-hash | 0 | 0/0/0 |
| xss-sink | 0 | 0/0/0 |

### Per case: deployready

| Case | Kind | TP | FP | FN | Extra | Alerts | Status | Scan (s) | Peak RSS (MB) | Missed | False positives |
|---|---|---|---|---|---|---|---|---|---|---|---|
| firebase/firestore-auth-only-users-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.39 | 100 | - | - |
| firebase/firestore-open-true-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.40 | 99 | - | - |
| firebase/firestore-owner-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.36 | 99 | - | - |
| firebase/firestore-public-read-warn-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.39 | 99 | - | - |
| firebase/firestore-recursive-wildcard-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.36 | 99 | - | - |
| firebase/firestore-test-mode-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.32 | 100 | - | - |
| firebase/ignored-service-account-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.32 | 100 | - | - |
| firebase/rtdb-auth-only-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.35 | 101 | - | - |
| firebase/rtdb-open-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.40 | 103 | - | - |
| firebase/rtdb-scoped-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.37 | 99 | - | - |
| firebase/service-account-committed-tp | pos | 1 | 0 | 0 | 1 | 3 | ok | 0.42 | 102 | - | - |
| firebase/storage-open-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.35 | 99 | - | - |
| firebase/storage-owner-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.37 | 99 | - | - |
| firebase/web-config-apikey-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.39 | 101 | - | - |
| idor/express-admin-guard-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.42 | 102 | - | - |
| idor/express-mongoose-owner-check-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.37 | 102 | - | - |
| idor/express-prisma-scoped-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.36 | 110 | - | - |
| idor/express-prisma-tp | pos | 1 | 0 | 0 | 0 | 3 | ok | 0.35 | 112 | - | - |
| idor/express-public-catalog-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.32 | 101 | - | - |
| idor/express-sql-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.36 | 103 | - | - |
| idor/fastapi-sqlalchemy-scoped-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.34 | 100 | - | - |
| idor/fastapi-sqlalchemy-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.36 | 107 | - | - |
| idor/flask-owner-check-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.35 | 108 | - | - |
| idor/flask-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.37 | 100 | - | - |
| idor/nextjs-supabase-rls-client-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.34 | 102 | - | - |
| idor/nextjs-supabase-scoped-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.37 | 110 | - | - |
| idor/nextjs-supabase-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.37 | 110 | - | - |
| rls/a01-anon-select-true-invoices-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 100 | - | - |
| rls/a02-authenticated-using-true-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.32 | 100 | - | - |
| rls/a03-auth-role-authenticated-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.34 | 100 | - | - |
| rls/a04-rls-disabled-later-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.37 | 103 | - | - |
| rls/a05-schema-shadow-public-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.34 | 99 | - | - |
| rls/a06-schema-shadow-exposed-api-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.32 | 102 | - | - |
| rls/a07-alter-policy-insecure-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.33 | 102 | - | - |
| rls/a08-unlogged-table-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.32 | 100 | - | - |
| rls/a09-tautology-read-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.32 | 102 | - | - |
| rls/a10-tautology-write-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.33 | 102 | - | - |
| rls/s01-owner-scoped-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.36 | 99 | - | - |
| rls/s02-dropped-and-replaced-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.39 | 101 | - | - |
| rls/s03-public-catalog-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 100 | - | - |
| rls/s04-tenant-membership-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.34 | 102 | - | - |
| rls/s05-private-schema-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.39 | 99 | - | - |
| rls/s06-service-role-and-restrictive-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.40 | 99 | - | - |
| rls/v01-rename-keeps-rls-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.39 | 102 | - | - |
| rls/v02-rename-unprotected-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.36 | 103 | - | - |
| rls/v03-set-schema-into-public-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 101 | - | - |
| rls/v04-set-schema-out-of-public-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 102 | - | - |
| rls/v05-long-history-secure-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.36 | 103 | - | - |
| rls/v06-long-history-regressed-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 103 | - | - |
| rls/v07-quoted-identifier-mismatch-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.36 | 99 | - | - |
| rls/v08-quoted-identifiers-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.33 | 100 | - | - |
| rls/v09-partition-child-unprotected-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.31 | 100 | - | - |
| rls/v10-restrictive-guard-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.32 | 100 | - | - |
| rls/v11-revoked-anon-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.39 | 110 | - | - |
| rls/v12-drop-recreate-without-rls-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.37 | 101 | - | - |
| rls/v13-config-public-table-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.39 | 100 | - | - |
| rls/v14-unknown-table-review-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.36 | 99 | - | - |
| rls/v15-config-sensitive-table-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 100 | - | - |
| rls/v16-membership-self-compare-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 100 | - | - |
| rls/v17-catalog-write-open-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 100 | - | - |
| rls/v18-disable-reenable-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.39 | 102 | - | - |
| rls/v19-do-block-enable-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.40 | 102 | - | - |
| rls/v20-auth-uid-not-null-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.39 | 99 | - | - |
| rls/v21-or-true-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.37 | 100 | - | - |
| rls/v22-search-path-private-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 100 | - | - |
| static/clean-project | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.42 | 110 | - | - |
| static/secret-tn-env-and-placeholder | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 100 | - | - |
| static/secret-tp-hardcoded-key | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.37 | 101 | - | - |
| static/sqli-fp-array-update-arith | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 100 | - | - |
| static/sqli-fp-crypto-hash-update | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.35 | 100 | - | - |
| static/sqli-fp-hash-update-template | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.37 | 100 | - | - |
| static/sqli-fp-orm-update | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 100 | - | - |
| static/sqli-fp-ui-string-delete | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 100 | - | - |
| static/sqli-fp-ui-string-update | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 100 | - | - |
| static/sqli-tn-parameterized-js | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 101 | - | - |
| static/sqli-tn-python-parameterized | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.39 | 100 | - | - |
| static/sqli-tp-concat-query | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 101 | - | - |
| static/sqli-tp-const-select | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 100 | - | - |
| static/sqli-tp-execute-delete | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.41 | 100 | - | - |
| static/sqli-tp-lowercase | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.43 | 101 | - | - |
| static/sqli-tp-python-format | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.41 | 100 | - | - |
| static/sqli-tp-python-fstring | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 99 | - | - |
| static/sqli-tp-template-literal | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.44 | 100 | - | - |
| static/walker-env-production-not-ignored | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.40 | 101 | - | - |
| static/walker-env-staging | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.40 | 101 | - | - |
| static/walker-github-workflow-secret | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 101 | - | - |
| static/walker-gitignored-dir | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.40 | 100 | - | - |
| static/walker-normal-source-flagged | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.47 | 101 | - | - |
| vibe/express-admin-auth-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.40 | 101 | - | - |
| vibe/express-admin-noauth-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.38 | 103 | - | - |
| vibe/express-cors-tls-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.37 | 100 | - | - |
| vibe/express-cors-tls-tp | pos | 2 | 0 | 0 | 0 | 2 | ok | 0.36 | 102 | - | - |
| vibe/express-idor-scoped-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 102 | - | - |
| vibe/express-idor-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.43 | 109 | - | - |
| vibe/express-jwt-hardcoded-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.42 | 101 | - | - |
| vibe/express-sqli-concat-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.35 | 103 | - | - |
| vibe/express-sqli-param-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.49 | 107 | - | - |
| vibe/fastapi-delete-noauth-tp | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.42 | 102 | - | - |
| vibe/flask-debug-sqli-tp | pos | 4 | 0 | 0 | 0 | 4 | ok | 0.41 | 102 | - | - |
| vibe/nextjs-client-secrets-tp | pos | 2 | 0 | 0 | 0 | 2 | ok | 0.42 | 101 | - | - |
| vibe/nextjs-server-service-role-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.44 | 102 | - | - |
| vibe/python-safe-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.39 | 100 | - | - |
| vibe/supabase-never-rls-tp | pos | 1 | 0 | 0 | 0 | 3 | ok | 0.48 | 102 | - | - |
| vibe/supabase-partial-rls-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.43 | 101 | - | - |
| vibe/supabase-rls-proper-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.48 | 99 | - | - |
| vibe/supabase-using-true-tp | pos | 1 | 0 | 0 | 0 | 4 | ok | 0.41 | 102 | - | - |
| vibe/vite-env-ignored-tn | pos | 0 | 0 | 0 | 0 | 0 | ok | 0.49 | 100 | - | - |
| vibe/vite-env-not-ignored-tp | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.44 | 100 | - | - |
