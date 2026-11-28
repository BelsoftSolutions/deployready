## HOLDOUT corpus (never used for tuning)

46 cases, 29 positive labels, 18 negative cases.

| Tool | TP | FP | TN | FN | Precision | Recall | F1 | Sev-weighted recall | Precision incl. extras | Extra | Other | Inconclusive | Neg. cases clean | Scan time total / mean / max (s) | Peak RSS mean / max (MB) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| deployready | 18 | 1 | 449 | 11 | 0.95 | 0.62 | 0.75 | 0.64 | 0.95 | 0 | 3 | 0 | 17/18 | 17.9 / 0.39 / 0.5 | 101 / 110 |
| semgrep | 11 | 8 | 442 | 18 | 0.58 | 0.38 | 0.46 | 0.39 | 0.41 | 8 | 6 | 0 | 11/18 | 1099.1 / 23.89 / 47.5 | 167 / 170 |
| llm | 28 | 19 | 433 | 1 | 0.60 | 0.97 | 0.74 | 0.96 | 0.36 | 31 | 58 | 0 | 7/18 | 599.0 / 13.02 / 21.5 | 221 / 227 |

### Per class (TP/FP/FN; TN omitted)

| Class | Labels | deployready | semgrep | llm |
|---|---|---|---|---|
| client-secret-exposure | 2 | 2/0/0 | 0/0/2 | 2/2/0 |
| code-injection | 1 | 1/0/0 | 1/0/0 | 1/1/0 |
| command-injection | 1 | 1/0/0 | 1/0/0 | 1/0/0 |
| cors | 1 | 0/0/1 | 1/0/0 | 1/1/0 |
| debug-mode | 1 | 1/0/0 | 1/0/0 | 1/1/0 |
| firebase-open-rules | 1 | 0/0/1 | 0/0/1 | 1/0/0 |
| hardcoded-secret | 1 | 1/0/0 | 1/0/0 | 1/1/0 |
| idor | 2 | 1/0/1 | 0/0/2 | 2/3/0 |
| insecure-cookie | 1 | 1/0/0 | 1/6/0 | 1/1/0 |
| jwt-misconfig | 1 | 0/0/1 | 1/0/0 | 0/0/1 |
| mass-assignment | 1 | 0/0/1 | 0/0/1 | 1/0/0 |
| missing-auth | 2 | 1/0/1 | 0/0/2 | 2/4/0 |
| nosql-injection | 1 | 0/0/1 | 0/0/1 | 1/0/0 |
| open-redirect | 1 | 0/0/1 | 0/0/1 | 1/1/0 |
| path-traversal | 1 | 0/0/1 | 0/1/1 | 1/1/0 |
| rls-missing | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| rls-permissive | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| secret-committed | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| sqli | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| ssrf | 1 | 0/0/1 | 1/1/0 | 1/1/0 |
| tls-disabled | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| unsafe-deserialization | 2 | 2/0/0 | 2/0/0 | 2/0/0 |
| weak-password-hash | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| webhook-signature-missing | 1 | 0/0/1 | 0/0/1 | 1/0/0 |
| xss | 1 | 1/1/0 | 1/0/0 | 1/2/0 |

### Per case: deployready

| Case | Kind | TP | FP | FN | Extra | Alerts | Status | Scan (s) | Peak RSS (MB) | Missed | False positives |
|---|---|---|---|---|---|---|---|---|---|---|---|
| h01-next-service-key-client | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.36 | 103 | - | - |
| h02-next-prisma-raw-sqli | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.34 | 101 | - | - |
| h03-express-prisma-idor | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.36 | 110 | - | - |
| h04-fastapi-command-injection | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.32 | 100 | - | - |
| h05-flask-pickle-load | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.31 | 100 | - | - |
| h06-stripe-webhook-unsigned | pos | 0 | 0 | 1 | 0 | 0 | ok | 0.32 | 101 | webhook-signature-missing (server.js) | - |
| h07-supabase-rls-never-enabled | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.37 | 102 | - | - |
| h08-supabase-policy-using-true | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.36 | 108 | - | - |
| h09-firebase-open-rules | pos | 0 | 0 | 1 | 0 | 2 | ok | 0.40 | 101 | firebase-open-rules (firestore.rules) | - |
| h10-flask-path-traversal | pos | 0 | 0 | 1 | 0 | 0 | ok | 0.36 | 99 | path-traversal (app.py) | - |
| h11-react-dangerous-html | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.40 | 100 | - | - |
| h12-fastapi-ssrf-fetch | pos | 0 | 0 | 1 | 0 | 0 | ok | 0.38 | 99 | ssrf (main.py) | - |
| h13-express-md5-passwords | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.40 | 101 | - | - |
| h14-express-jwt-decode-only | pos | 0 | 0 | 1 | 0 | 0 | ok | 0.47 | 100 | jwt-misconfig (server.js) | - |
| h15-express-mass-assignment | pos | 0 | 0 | 1 | 0 | 0 | ok | 0.41 | 101 | mass-assignment (routes.js) | - |
| h16-express-session-cookie-weak | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.42 | 101 | - | - |
| h17-flask-yaml-load-debug | pos | 2 | 0 | 0 | 0 | 2 | ok | 0.39 | 99 | - | - |
| h18-next-open-redirect | pos | 0 | 0 | 1 | 0 | 0 | ok | 0.40 | 100 | open-redirect (app/login/callback/route.ts) | - |
| h19-tenant-list-unscoped | pos | 0 | 0 | 1 | 0 | 0 | ok | 0.42 | 100 | idor (server.js) | - |
| h20-express-admin-no-auth | pos | 1 | 0 | 0 | 0 | 2 | ok | 0.39 | 104 | - | - |
| h21-vite-env-committed | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.34 | 100 | - | - |
| h22-express-cors-reflect-credentials | pos | 0 | 0 | 1 | 0 | 0 | ok | 0.35 | 100 | cors (server.js) | - |
| h23-python-hardcoded-creds | pos | 1 | 0 | 0 | 0 | 3 | ok | 0.38 | 102 | - | - |
| h24-node-tls-reject-off | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 101 | - | - |
| h25-next-public-openai-key | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.38 | 101 | - | - |
| h26-express-eval-input | pos | 1 | 0 | 0 | 0 | 1 | ok | 0.39 | 100 | - | - |
| h27-next-server-action-no-auth | pos | 0 | 0 | 1 | 0 | 0 | ok | 0.48 | 108 | missing-auth (app/actions.ts) | - |
| h28-express-nosql-injection | pos | 0 | 0 | 1 | 0 | 0 | ok | 0.45 | 100 | nosql-injection (server.js) | - |
| n01-supabase-rls-owner-policies | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.45 | 101 | - | - |
| n02-express-prisma-scoped | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.47 | 109 | - | - |
| n03-fastapi-safe-subprocess | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 99 | - | - |
| n04-flask-safe-config | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.35 | 99 | - | - |
| n05-stripe-webhook-verified | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.42 | 100 | - | - |
| n06-firebase-scoped-rules | neg | 0 | 0 | 0 | 0 | 1 | ok | 0.41 | 99 | - | - |
| n07-express-hardened | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.39 | 102 | - | - |
| n08-env-example-only | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.40 | 100 | - | - |
| n09-pg-parameterized | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.43 | 101 | - | - |
| n10-react-safe-render | neg | 0 | 1 | 0 | 0 | 1 | ok | 0.39 | 102 | - | xss src/Comments.jsx:8 [xss-sink] |
| n11-fastapi-ssrf-allowlist | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 100 | - | - |
| n12-supabase-tenant-rls | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.43 | 100 | - | - |
| n13-next-safe-redirect-cookies | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.42 | 101 | - | - |
| n14-next-server-action-authed | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.44 | 101 | - | - |
| n15-python-env-secrets | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 100 | - | - |
| n16-express-tenant-scoped | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.38 | 102 | - | - |
| n17-express-safe-misc | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.33 | 101 | - | - |
| n18-firebase-client-config | neg | 0 | 0 | 0 | 0 | 0 | ok | 0.34 | 101 | - | - |

### Per case: semgrep

| Case | Kind | TP | FP | FN | Extra | Alerts | Status | Scan (s) | Peak RSS (MB) | Missed | False positives |
|---|---|---|---|---|---|---|---|---|---|---|---|
| h01-next-service-key-client | pos | 0 | 0 | 1 | 0 | 0 | ok | 29.82 | 169 | client-secret-exposure (lib/supabase.ts) | - |
| h02-next-prisma-raw-sqli | pos | 0 | 0 | 1 | 0 | 0 | ok | 36.21 | 169 | sqli (app/api/search/route.ts) | - |
| h03-express-prisma-idor | pos | 0 | 0 | 1 | 1 | 1 | ok | 21.41 | 167 | idor (server.js) | - |
| h04-fastapi-command-injection | pos | 1 | 0 | 0 | 0 | 2 | ok | 21.54 | 169 | - | - |
| h05-flask-pickle-load | pos | 1 | 0 | 0 | 0 | 3 | ok | 29.96 | 167 | - | - |
| h06-stripe-webhook-unsigned | pos | 0 | 0 | 1 | 1 | 1 | ok | 31.64 | 168 | webhook-signature-missing (server.js) | - |
| h07-supabase-rls-never-enabled | pos | 0 | 0 | 1 | 0 | 0 | ok | 21.64 | 168 | rls-missing (supabase/migrations/20240101000000_init.sql) | - |
| h08-supabase-policy-using-true | pos | 0 | 0 | 1 | 0 | 0 | ok | 20.38 | 166 | rls-permissive (supabase/migrations/20240201000000_notes.sql) | - |
| h09-firebase-open-rules | pos | 0 | 0 | 1 | 0 | 0 | ok | 20.64 | 167 | firebase-open-rules (firestore.rules) | - |
| h10-flask-path-traversal | pos | 0 | 0 | 1 | 0 | 0 | ok | 21.20 | 167 | path-traversal (app.py) | - |
| h11-react-dangerous-html | pos | 1 | 0 | 0 | 0 | 1 | ok | 23.47 | 167 | - | - |
| h12-fastapi-ssrf-fetch | pos | 1 | 0 | 0 | 0 | 2 | ok | 20.31 | 167 | - | - |
| h13-express-md5-passwords | pos | 0 | 0 | 1 | 0 | 0 | ok | 21.88 | 167 | weak-password-hash (auth.js) | - |
| h14-express-jwt-decode-only | pos | 1 | 0 | 0 | 1 | 2 | ok | 20.65 | 166 | - | - |
| h15-express-mass-assignment | pos | 0 | 0 | 1 | 0 | 0 | ok | 22.60 | 167 | mass-assignment (routes.js) | - |
| h16-express-session-cookie-weak | pos | 1 | 0 | 0 | 0 | 7 | ok | 21.32 | 167 | - | - |
| h17-flask-yaml-load-debug | pos | 2 | 0 | 0 | 0 | 4 | ok | 21.18 | 168 | - | - |
| h18-next-open-redirect | pos | 0 | 0 | 1 | 0 | 0 | ok | 20.32 | 165 | open-redirect (app/login/callback/route.ts) | - |
| h19-tenant-list-unscoped | pos | 0 | 0 | 1 | 1 | 1 | ok | 19.24 | 167 | idor (server.js) | - |
| h20-express-admin-no-auth | pos | 0 | 0 | 1 | 1 | 1 | ok | 19.88 | 167 | missing-auth (server.js) | - |
| h21-vite-env-committed | pos | 0 | 0 | 1 | 0 | 0 | ok | 20.03 | 164 | secret-committed (.env) | - |
| h22-express-cors-reflect-credentials | pos | 1 | 0 | 0 | 1 | 2 | ok | 20.07 | 168 | - | - |
| h23-python-hardcoded-creds | pos | 1 | 0 | 0 | 0 | 2 | ok | 19.76 | 168 | - | - |
| h24-node-tls-reject-off | pos | 0 | 0 | 1 | 0 | 0 | ok | 20.78 | 166 | tls-disabled (lib/http.js) | - |
| h25-next-public-openai-key | pos | 0 | 0 | 1 | 0 | 1 | ok | 19.53 | 165 | client-secret-exposure (components/Chat.tsx) | - |
| h26-express-eval-input | pos | 1 | 0 | 0 | 1 | 3 | ok | 19.76 | 166 | - | - |
| h27-next-server-action-no-auth | pos | 0 | 0 | 1 | 0 | 0 | ok | 20.39 | 169 | missing-auth (app/actions.ts) | - |
| h28-express-nosql-injection | pos | 0 | 0 | 1 | 1 | 1 | ok | 20.55 | 168 | nosql-injection (server.js) | - |
| n01-supabase-rls-owner-policies | neg | 0 | 0 | 0 | 0 | 0 | ok | 19.43 | 165 | - | - |
| n02-express-prisma-scoped | neg | 0 | 1 | 0 | 0 | 1 | ok | 20.86 | 168 | - | insecure-cookie server.js:5 [express-check-csurf-middleware-usage] |
| n03-fastapi-safe-subprocess | neg | 0 | 0 | 0 | 0 | 0 | ok | 18.81 | 168 | - | - |
| n04-flask-safe-config | neg | 0 | 0 | 0 | 0 | 0 | ok | 19.61 | 169 | - | - |
| n05-stripe-webhook-verified | neg | 0 | 1 | 0 | 0 | 2 | ok | 18.74 | 167 | - | insecure-cookie server.js:4 [express-check-csurf-middleware-usage] |
| n06-firebase-scoped-rules | neg | 0 | 0 | 0 | 0 | 0 | ok | 19.97 | 164 | - | - |
| n07-express-hardened | neg | 0 | 1 | 0 | 0 | 5 | ok | 21.48 | 168 | - | insecure-cookie server.js:8 [express-check-csurf-middleware-usage] |
| n08-env-example-only | neg | 0 | 0 | 0 | 0 | 0 | ok | 19.76 | 166 | - | - |
| n09-pg-parameterized | neg | 0 | 1 | 0 | 0 | 1 | ok | 19.71 | 168 | - | insecure-cookie server.js:3 [express-check-csurf-middleware-usage] |
| n10-react-safe-render | neg | 0 | 0 | 0 | 0 | 0 | ok | 20.16 | 167 | - | - |
| n11-fastapi-ssrf-allowlist | neg | 0 | 1 | 0 | 0 | 2 | ok | 19.46 | 170 | - | ssrf main.py:15 [ssrf-requests] |
| n12-supabase-tenant-rls | neg | 0 | 0 | 0 | 0 | 0 | ok | 19.47 | 165 | - | - |
| n13-next-safe-redirect-cookies | neg | 0 | 0 | 0 | 0 | 0 | ok | 41.37 | 169 | - | - |
| n14-next-server-action-authed | neg | 0 | 0 | 0 | 0 | 0 | ok | 40.04 | 168 | - | - |
| n15-python-env-secrets | neg | 0 | 0 | 0 | 0 | 0 | ok | 39.28 | 167 | - | - |
| n16-express-tenant-scoped | neg | 0 | 1 | 0 | 0 | 1 | ok | 38.97 | 167 | - | insecure-cookie server.js:4 [express-check-csurf-middleware-usage] |
| n17-express-safe-misc | neg | 0 | 2 | 0 | 0 | 6 | ok | 47.55 | 168 | - | insecure-cookie server.js:4 [express-check-csurf-middleware-usage]; path-traversal server.js:10 [express-path-join-resolve-traversal] |
| n18-firebase-client-config | neg | 0 | 0 | 0 | 0 | 0 | ok | 28.30 | 168 | - | - |

### Per case: llm

| Case | Kind | TP | FP | FN | Extra | Alerts | Status | Scan (s) | Peak RSS (MB) | Missed | False positives |
|---|---|---|---|---|---|---|---|---|---|---|---|
| h01-next-service-key-client | pos | 1 | 0 | 0 | 1 | 5 | ok | 15.66 | 220 | - | - |
| h02-next-prisma-raw-sqli | pos | 1 | 0 | 0 | 1 | 5 | ok | 8.83 | 219 | - | - |
| h03-express-prisma-idor | pos | 1 | 0 | 0 | 0 | 9 | ok | 17.13 | 221 | - | - |
| h04-fastapi-command-injection | pos | 1 | 0 | 0 | 1 | 6 | ok | 16.87 | 226 | - | - |
| h05-flask-pickle-load | pos | 1 | 0 | 0 | 1 | 6 | ok | 9.43 | 225 | - | - |
| h06-stripe-webhook-unsigned | pos | 1 | 0 | 0 | 1 | 11 | ok | 17.34 | 221 | - | - |
| h07-supabase-rls-never-enabled | pos | 1 | 0 | 0 | 2 | 5 | ok | 12.71 | 220 | - | - |
| h08-supabase-policy-using-true | pos | 1 | 0 | 0 | 1 | 3 | ok | 9.61 | 221 | - | - |
| h09-firebase-open-rules | pos | 1 | 0 | 0 | 3 | 6 | ok | 7.25 | 221 | - | - |
| h10-flask-path-traversal | pos | 1 | 0 | 0 | 1 | 5 | ok | 8.00 | 225 | - | - |
| h11-react-dangerous-html | pos | 1 | 0 | 0 | 0 | 1 | ok | 6.96 | 221 | - | - |
| h12-fastapi-ssrf-fetch | pos | 1 | 0 | 0 | 1 | 6 | ok | 11.12 | 226 | - | - |
| h13-express-md5-passwords | pos | 1 | 0 | 0 | 0 | 7 | ok | 15.97 | 220 | - | - |
| h14-express-jwt-decode-only | pos | 0 | 0 | 1 | 1 | 7 | ok | 9.85 | 219 | jwt-misconfig (server.js) | - |
| h15-express-mass-assignment | pos | 1 | 0 | 0 | 2 | 8 | ok | 10.87 | 219 | - | - |
| h16-express-session-cookie-weak | pos | 1 | 0 | 0 | 1 | 8 | ok | 11.99 | 221 | - | - |
| h17-flask-yaml-load-debug | pos | 2 | 0 | 0 | 2 | 9 | ok | 10.73 | 225 | - | - |
| h18-next-open-redirect | pos | 1 | 0 | 0 | 1 | 3 | ok | 8.66 | 221 | - | - |
| h19-tenant-list-unscoped | pos | 1 | 0 | 0 | 0 | 5 | ok | 11.19 | 220 | - | - |
| h20-express-admin-no-auth | pos | 1 | 0 | 0 | 1 | 7 | ok | 10.64 | 219 | - | - |
| h21-vite-env-committed | pos | 1 | 0 | 0 | 3 | 10 | ok | 9.26 | 220 | - | - |
| h22-express-cors-reflect-credentials | pos | 1 | 0 | 0 | 1 | 6 | ok | 10.40 | 220 | - | - |
| h23-python-hardcoded-creds | pos | 1 | 0 | 0 | 0 | 5 | ok | 10.26 | 221 | - | - |
| h24-node-tls-reject-off | pos | 1 | 0 | 0 | 1 | 7 | ok | 9.46 | 219 | - | - |
| h25-next-public-openai-key | pos | 1 | 0 | 0 | 1 | 4 | ok | 11.52 | 221 | - | - |
| h26-express-eval-input | pos | 1 | 0 | 0 | 1 | 6 | ok | 8.50 | 221 | - | - |
| h27-next-server-action-no-auth | pos | 1 | 0 | 0 | 1 | 8 | ok | 14.78 | 219 | - | - |
| h28-express-nosql-injection | pos | 1 | 0 | 0 | 2 | 9 | ok | 11.88 | 220 | - | - |
| n01-supabase-rls-owner-policies | neg | 0 | 2 | 0 | 0 | 4 | ok | 17.13 | 219 | - | client-secret-exposure lib/supabase-server.ts:5 [The service-role client bypasses all RLS policies. Any server code that passes u]; client-secret-exposure supabase/migrations/20240101000000_init.sql:16 [The insert policy lets any authenticated user create orders directly with a clie] |
| n02-express-prisma-scoped | neg | 0 | 0 | 0 | 0 | 8 | ok | 17.63 | 219 | - | - |
| n03-fastapi-safe-subprocess | neg | 0 | 0 | 0 | 0 | 4 | ok | 14.45 | 225 | - | - |
| n04-flask-safe-config | neg | 0 | 4 | 0 | 0 | 7 | ok | 14.60 | 227 | - | missing-auth app.py:12 [/api/config/import has no authentication or authorization. Any client that can r]; path-traversal app.py:18 [Path traversal is mitigated by secure_filename and send_from_directory, but the ]; code-injection app.py:22 [debug is enabled whenever FLASK_DEBUG=1. The Werkzeug debugger allows arbitrary ]; debug-mode app.py:22 [debug is enabled whenever FLASK_DEBUG=1. The Werkzeug debugger allows arbitrary ] |
| n05-stripe-webhook-verified | neg | 0 | 0 | 0 | 0 | 7 | ok | 14.54 | 219 | - | - |
| n06-firebase-scoped-rules | neg | 0 | 1 | 0 | 0 | 7 | ok | 10.88 | 221 | - | missing-auth firestore.rules:8 [Posts are publicly readable with allow read: if true, with no unauthenticated-ac] |
| n07-express-hardened | neg | 0 | 2 | 0 | 0 | 11 | ok | 19.87 | 220 | - | xss server.js:21 [The access token is returned in the JSON response body, which encourages client-]; insecure-cookie server.js:15 [The session cookie is marked secure: true, but the server only listens on plain ] |
| n08-env-example-only | neg | 0 | 0 | 0 | 0 | 6 | ok | 13.26 | 219 | - | - |
| n09-pg-parameterized | neg | 0 | 3 | 0 | 0 | 8 | ok | 16.56 | 219 | - | missing-auth db.js:7 [byOwner runs SELECT * with no authorization check on ownerId. If it is exposed b]; idor db.js:7 [byOwner runs SELECT * with no authorization check on ownerId. If it is exposed b]; missing-auth server.js:4 [/search has no authentication and no rate limiting, so anonymous clients can sen] |
| n10-react-safe-render | neg | 0 | 1 | 0 | 0 | 4 | ok | 16.22 | 220 | - | xss src/Comments.jsx:8 [Stored XSS risk, defense-in-depth only: comment.body is rendered as raw HTML via] |
| n11-fastapi-ssrf-allowlist | neg | 0 | 1 | 0 | 0 | 4 | ok | 18.98 | 225 | - | ssrf main.py:15 [SSRF via parser differential: the allowlist is checked on urlparse(url) (line 13] |
| n12-supabase-tenant-rls | neg | 0 | 0 | 0 | 0 | 4 | ok | 21.51 | 220 | - | - |
| n13-next-safe-redirect-cookies | neg | 0 | 1 | 0 | 0 | 3 | ok | 13.09 | 221 | - | open-redirect app/login/callback/route.ts:7 [Open redirect bypass. The check only rejects strings starting with '//', but bro] |
| n14-next-server-action-authed | neg | 0 | 1 | 0 | 0 | 4 | ok | 12.56 | 221 | - | idor app/actions.ts:8 [Authorization depends on session.user.id, but the check only tests session?.user] |
| n15-python-env-secrets | neg | 0 | 0 | 0 | 0 | 2 | ok | 10.06 | 219 | - | - |
| n16-express-tenant-scoped | neg | 0 | 2 | 0 | 0 | 12 | ok | 14.58 | 221 | - | idor server.js:19 [Tenant-isolation depends on req.user.orgId being defined. If requireAuth ever se]; cors server.js:23 [app.listen(3000) binds to all interfaces with plain HTTP and no TLS, helmet secu] |
| n17-express-safe-misc | neg | 0 | 0 | 0 | 0 | 4 | ok | 17.26 | 221 | - | - |
| n18-firebase-client-config | neg | 0 | 1 | 0 | 0 | 8 | ok | 19.00 | 220 | - | hardcoded-secret src/firebase.js:8 [projectId is hardcoded to 'demo-app' while apiKey comes from the environment. Th] |
