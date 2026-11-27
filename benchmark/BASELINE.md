# Benchmark baseline

Captured with `npx tsx benchmark/run.ts` on base commit 9cf6182 (detection code unchanged). Re-run after rule changes and diff.
"SUPPORTED RULES" excludes labels for issues no rule covers yet; "TOTAL" counts those as misses.
Cases under `corpus/vibe` are the vibe-coded app set.

```
DeployReady benchmark

PASS  static  clean-project                                     P=- R=-
PASS  static  secret-tn-env-and-placeholder                     P=- R=-
PASS  static  secret-tp-hardcoded-key                           P=1.00 R=1.00
PASS  static  sqli-fp-array-update-arith                        P=- R=-
PASS  static  sqli-fp-crypto-hash-update                        P=- R=-
PASS  static  sqli-fp-hash-update-template                      P=- R=-
PASS  static  sqli-fp-orm-update                                P=- R=-
PASS  static  sqli-fp-ui-string-delete                          P=- R=-
PASS  static  sqli-fp-ui-string-update                          P=- R=-
PASS  static  sqli-tn-parameterized-js                          P=- R=-
PASS  static  sqli-tn-python-parameterized                      P=- R=-
PASS  static  sqli-tp-concat-query                              P=1.00 R=1.00
PASS  static  sqli-tp-const-select                              P=1.00 R=1.00
PASS  static  sqli-tp-execute-delete                            P=1.00 R=1.00
PASS  static  sqli-tp-lowercase                                 P=1.00 R=1.00
GAP   static  sqli-tp-python-format                             P=- R=0.00  [py-sql-fstring claims format (extra to audit item P1-4)]
        MISSED: py-sql-fstring present (app.py) -> not found
PASS  static  sqli-tp-python-fstring                            P=1.00 R=1.00
PASS  static  sqli-tp-template-literal                          P=1.00 R=1.00
PASS  static  walker-env-production-not-ignored                 P=1.00 R=1.00
PASS  static  walker-env-staging                                P=1.00 R=1.00
PASS  static  walker-github-workflow-secret                     P=1.00 R=1.00
PASS  static  walker-gitignored-dir                             P=- R=-
PASS  static  walker-normal-source-flagged                      P=1.00 R=1.00
PASS  parser  guard-extra-handler-not-auth                      P=- R=-
PASS  parser  guard-named-middleware                            P=1.00 R=1.00
PASS  parser  guard-prefix-use-leaves-others-open               P=- R=-
PASS  parser  guard-prefix-use-protects-prefix                  P=1.00 R=1.00
PASS  parser  guard-public-routes                               P=- R=-
PASS  parser  guard-router-use-after-route                      P=- R=-
PASS  parser  guard-router-use-before-routes                    P=1.00 R=1.00
PASS  parser  guard-validation-middleware                       P=- R=-
GAP   parser  py-guard-depends-in-signature                     P=- R=0.00  [audit item P1-6]
        MISSED: GET /profile guarded -> parser: unguarded
PASS  parser  py-guard-depends-inline                           P=1.00 R=1.00
GAP   parser  py-guard-path-contains-auth                       P=0.00 R=-  [audit item P1-6]
        UNEXPECTED: GET /authors unguarded -> parser: guarded
        UNEXPECTED: GET /oauth/callback unguarded -> parser: guarded
GAP   vibe    express-admin-auth-tn                             P=0.67 R=1.00  [possible-hardcoded-secret fires on a token-named variable assigned from a header expression]
        UNEXPECTED: possible-hardcoded-secret absent -> found 1: server.js:8 warning
PASS  vibe    express-admin-noauth-tp                           P=- R=0.00
PASS  vibe    express-cors-tls-tn                               P=- R=-
PASS  vibe    express-cors-tls-tp                               P=1.00 R=1.00
PASS  vibe    express-idor-scoped-tn                            P=1.00 R=1.00
PASS  vibe    express-idor-tp                                   P=- R=0.00
PASS  vibe    express-jwt-hardcoded-tp                          P=1.00 R=1.00
PASS  vibe    express-sqli-concat-tp                            P=1.00 R=1.00
GAP   vibe    express-sqli-param-tn                             P=0.00 R=-  [sql-injection fires on a parameterized query whose bound LIKE value is built with a template literal]
        UNEXPECTED: sql-injection absent -> found 1: server.js:7 critical
PASS  vibe    fastapi-delete-noauth-tp                          P=- R=0.00
GAP   vibe    flask-debug-sqli-tp                               P=1.00 R=0.50  [py-sql-fstring misses f-strings that quote values with single quotes inside double quotes; no rule for Flask config["SECRET_KEY"] literals]
        MISSED: py-sql-fstring present (app.py) -> not found
        MISSED: possible-hardcoded-secret present (app.py) -> not found
PASS  vibe    nextjs-client-secrets-tp                          P=1.00 R=0.50
GAP   vibe    nextjs-server-service-role-tn                     P=0.00 R=-  [supabase-service-role matches the bare name even in a server-only module]
        UNEXPECTED: supabase-service-role absent -> found 1: lib/supabaseAdmin.ts:7 warning
GAP   vibe    python-safe-tn                                    P=0.00 R=0.00  [possible-hardcoded-secret fires on a comparison literal; parser does not see Depends(...) in a signature as a guard (audit item P1-6)]
        UNEXPECTED: possible-hardcoded-secret absent -> found 1: api.py:9 warning
        MISSED: DELETE /items/{item_id} guarded -> parser: unguarded
GAP   vibe    supabase-never-rls-tp                             P=- R=0.00  [rls-not-enabled is gated on RLS being enabled somewhere, so projects that never enable RLS get nothing]
        MISSED: rls-not-enabled present (supabase/migrations/20240101000000_init.sql) -> not found
PASS  vibe    supabase-partial-rls-tp                           P=1.00 R=1.00
PASS  vibe    supabase-rls-proper-tn                            P=- R=-
PASS  vibe    supabase-using-true-tp                            P=- R=0.00
PASS  vibe    vite-env-ignored-tn                               P=- R=-
PASS  vibe    vite-env-not-ignored-tp                           P=1.00 R=1.00
PASS  dynamic admin-401                                         P=- R=-
PASS  dynamic admin-401-backoffice-discovered                   P=- R=-
PASS  dynamic admin-401-discovered                              P=- R=-
PASS  dynamic admin-403-staff-console-discovered                P=- R=-
GAP   dynamic admin-open-200                                    P=- R=0.00  [route not discovered by the parser; DeployReady no longer guesses routes]
        MISSED: exposed-admin-route present (/admin) -> not found
PASS  dynamic admin-open-200-discovered                         P=1.00 R=1.00
PASS  dynamic admin-open-backoffice-discovered                  P=1.00 R=1.00
PASS  dynamic admin-open-neutral-path-staff-guard               P=1.00 R=1.00
PASS  dynamic admin-open-staff-console-discovered               P=1.00 R=1.00
PASS  dynamic admin-redirect-staff-console-discovered           P=- R=-
PASS  dynamic admin-redirect-to-login                           P=- R=-
PASS  dynamic admin-redirect-to-login-discovered                P=- R=-
PASS  dynamic advertised-link-backoffice-open                   P=1.00 R=1.00
PASS  dynamic advertised-link-depth-one                         P=- R=-
PASS  dynamic advertised-link-spa-catchall-no-finding           P=- R=-
PASS  dynamic advertised-link-unsafe-and-foreign-not-requested  P=- R=-
PASS  dynamic auth-bypass-enforced                              P=- R=-
PASS  dynamic auth-bypass-open                                  P=1.00 R=1.00
GAP   dynamic catchall-env-exposed                              P=- R=0.00  [route not discovered by the parser; DeployReady no longer guesses routes]
        MISSED: exposed-admin-route present (/.env) -> not found
GAP   dynamic catchall-env-exposed-discovered                   P=- R=0.00  [a discovered /.env route is requested but not classified sensitive (admin vocabulary has no secret-file names); only the secret-in-response warning fires]
        MISSED: exposed-admin-route present (/.env) -> not found
PASS  dynamic clean-app                                         P=- R=-
PASS  dynamic neutral-path-unguarded-open                       P=- R=-
PASS  dynamic no-routes-discovered-note                         P=1.00 R=1.00
PASS  dynamic path-param-route-skipped-alongside-probed         P=1.00 R=1.00
PASS  dynamic path-param-route-skipped-note                     P=1.00 R=1.00
PASS  dynamic ratelimit-limiter-all-methods                     P=- R=-
PASS  dynamic ratelimit-limiter-post-only                       P=- R=-
PASS  dynamic ratelimit-login-page-get                          P=- R=-
PASS  dynamic ratelimit-post-login-open                         P=1.00 R=1.00
PASS  dynamic robots-sitemap-not-evidence-not-requested         P=- R=-
PASS  dynamic secret-json-clean                                 P=- R=-
PASS  dynamic secret-json-nested                                P=1.00 R=1.00
PASS  dynamic secret-plain-text                                 P=1.00 R=1.00
PASS  dynamic spa-catchall-no-admin                             P=- R=-
PASS  dynamic spa-catchall-no-admin-discovered                  P=- R=-
PASS  dynamic spa-catchall-no-auth-bypass                       P=- R=-
PASS  active  bola-foreign-id-not-echoed                        P=1.00 R=1.00
PASS  active  bola-isolated-403                                 P=- R=-
PASS  active  bola-isolated-404                                 P=- R=-
PASS  active  bola-numeric-id-echoed                            P=1.00 R=1.00
GAP   active  bola-public-resource                              P=0.00 R=-  [audit item P2-8]
        UNEXPECTED: bola-idor absent -> found 1: /api/products/1 critical
PASS  active  bola-string-ids                                   P=1.00 R=1.00
PASS  active  jwt-first-public-second-secure                    P=- R=-
PASS  active  jwt-first-public-second-vulnerable                P=1.00 R=1.00
PASS  active  jwt-first-public-second-vulnerable-endpoint       P=1.00 R=1.00
PASS  active  jwt-protected-accepts-alg-none                    P=1.00 R=1.00
PASS  active  jwt-protected-rejects-alg-none                    P=- R=-
PASS  active  jwt-public-route                                  P=- R=-
PASS  active  tenant-isolated-403                               P=- R=-
PASS  active  tenant-numeric-path-param                         P=1.00 R=1.00
PASS  active  tenant-query-param                                P=1.00 R=1.00
PASS  active  tenant-string-path-param                          P=1.00 R=1.00

Rule                                   TP  FP  FN  TN  Precision  Recall
------------------------------------------------------------------------
auth-bypass                             2   0   0   5       1.00    1.00
bola-idor                               3   1   0   3       0.75    1.00
command-injection                       0   0   0   1          -       -
cors-wildcard                           1   0   0   2       1.00    1.00
cors-wildcard-live                      0   0   0   1          -       -
debug-enabled                           0   0   0   1          -       -
dynamic-routes-skipped                  1   0   0   0       1.00    1.00
dynamic-skipped                         2   0   0   1       1.00    1.00
env-not-ignored                         3   0   0   2       1.00    1.00
eval-usage                              1   0   0   2       1.00    1.00
exposed-admin-route                     5   0   3  16       1.00    0.63
hardcoded-secret                        2   0   0   2       1.00    1.00
insecure-cookie                         0   0   0   1          -       -
insecure-http-url                       0   0   0   1          -       -
insecure-random                         0   0   0   1          -       -
jwt-none-alg                            0   0   0   1          -       -
jwt-not-verified                        3   0   0   3       1.00    1.00
log-injection                           0   0   0   1          -       -
missing-cache-headers                   0   0   0   1          -       -
missing-rate-limit                      1   0   0   5       1.00    1.00
missing-security-headers                0   0   0   3          -       -
note-scored                             0   0   0   3          -       -
possible-hardcoded-secret               1   2   1   2       0.33    0.50
py-flask-debug                          1   0   0   1       1.00    1.00
py-requests-noverify                    1   0   0   1       1.00    1.00
py-sql-fstring                          1   0   2   2       1.00    0.33
rls-not-enabled                         1   0   1   3       1.00    0.50
route-guarded                          10   2   2  14       0.83    0.83
secret-in-response                      2   0   0   4       1.00    1.00
sql-injection                           6   1   0   9       0.86    1.00
stack-trace-leak                        0   0   0   1          -       -
supabase-service-role                   1   1   0   0       0.50    1.00
tenant-isolation-broken                 3   0   0   3       1.00    1.00
tls-verification-disabled               1   0   0   2       1.00    1.00
unrequested-path                        0   0   0  20          -       -
unsupported:idor                        0   0   1   0          -    0.00
unsupported:missing-auth-admin-route    0   0   2   0          -    0.00
unsupported:next-public-secret          0   0   1   0          -    0.00
unsupported:permissive-rls-policy       0   0   1   0          -    0.00
version-banner                          0   0   0   1          -       -
weak-hash                               0   0   0   1          -       -
xss-sink                                0   0   0   1          -       -
------------------------------------------------------------------------
SUPPORTED RULES                        52   7   9 121       0.88    0.85
TOTAL (incl. unsupported)              52   7  14 121       0.88    0.79

MISSES (expected but not reported): 14
  [rule]    sqli-tp-python-format: py-sql-fstring present (app.py) -> not found
  [rule]    py-guard-depends-in-signature: GET /profile guarded -> parser: unguarded
  [no rule] express-admin-noauth-tp: missing-auth-admin-route present (server.js) -> unauthenticated admin/delete route is only visible in the route graph, not reported as a finding
  [no rule] express-idor-tp: idor present (server.js) -> findByPk(req.params.id) with no req.user ownership filter
  [no rule] fastapi-delete-noauth-tp: missing-auth-admin-route present (main.py) -> unauthenticated delete/admin route is only visible in the route graph, not reported as a finding
  [rule]    flask-debug-sqli-tp: py-sql-fstring present (app.py) -> not found
  [rule]    flask-debug-sqli-tp: possible-hardcoded-secret present (app.py) -> not found
  [no rule] nextjs-client-secrets-tp: next-public-secret present (app/chat.tsx) -> NEXT_PUBLIC_ variable holding a secret key is inlined into the client bundle
  [rule]    python-safe-tn: DELETE /items/{item_id} guarded -> parser: unguarded
  [rule]    supabase-never-rls-tp: rls-not-enabled present (supabase/migrations/20240101000000_init.sql) -> not found
  [no rule] supabase-using-true-tp: permissive-rls-policy present (supabase/migrations/20240101000000_init.sql) -> policy with using (true) grants all rows to every role
  [rule]    admin-open-200: exposed-admin-route present (/admin) -> not found
  [rule]    catchall-env-exposed: exposed-admin-route present (/.env) -> not found
  [rule]    catchall-env-exposed-discovered: exposed-admin-route present (/.env) -> not found

FALSE POSITIVES (reported but should not be): 7
  py-guard-path-contains-auth: GET /authors unguarded -> parser: guarded
  py-guard-path-contains-auth: GET /oauth/callback unguarded -> parser: guarded
  express-admin-auth-tn: possible-hardcoded-secret absent -> found 1: server.js:8 warning
  express-sqli-param-tn: sql-injection absent -> found 1: server.js:7 critical
  nextjs-server-service-role-tn: supabase-service-role absent -> found 1: lib/supabaseAdmin.ts:7 warning
  python-safe-tn: possible-hardcoded-secret absent -> found 1: api.py:9 warning
  bola-public-resource: bola-idor absent -> found 1: /api/products/1 critical

Cases: 106  pass: 93  fail: 0  error: 0  known gap: 13  fixed (remove knownGap): 0
RESULT: OK
```
