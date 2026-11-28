/**
 * Tool output -> issue CLASS mapping for the holdout benchmark. Maintained separately from the labels
 * (holdout/labels.json) so ground truth is by class, never by DeployReady rule id.
 *
 * Written BEFORE any tool was run on the holdout; changes after seeing results must be logged in
 * HOLDOUT-RESULTS.md ("Mapping / label fixes"). Alerts outside the taxonomy map to 'other' (never penalised).
 */
export const CLASSES = [
  'sqli', 'nosql-injection', 'command-injection', 'code-injection', 'unsafe-deserialization', 'path-traversal',
  'xss', 'ssrf', 'open-redirect', 'missing-auth', 'idor', 'hardcoded-secret', 'secret-committed',
  'client-secret-exposure', 'cors', 'tls-disabled', 'debug-mode', 'rls-missing', 'rls-permissive',
  'firebase-open-rules', 'webhook-signature-missing', 'weak-password-hash', 'jwt-misconfig', 'mass-assignment',
  'insecure-cookie',
] as const;
export type IssueClass = (typeof CLASSES)[number];
export type MappedClass = IssueClass | 'other';

export const SEVERITY_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/** DeployReady rule id -> class. Unlisted rule ids are 'other'. */
export const DR_CLASS: Record<string, IssueClass> = {
  'sql-injection': 'sqli', 'py-sql-fstring': 'sqli',
  'command-injection': 'command-injection', 'py-os-system': 'command-injection', 'py-shell-injection': 'command-injection',
  'eval-usage': 'code-injection', 'py-eval-exec': 'code-injection',
  'py-pickle-loads': 'unsafe-deserialization', 'py-yaml-load': 'unsafe-deserialization',
  'xss-sink': 'xss',
  'missing-auth-route': 'missing-auth', 'auth-bypass': 'missing-auth', 'exposed-admin-route': 'missing-auth',
  'bola-idor': 'idor', 'idor-missing-ownership-check': 'idor', 'supabase-cross-user-read': 'idor',
  'hardcoded-secret': 'hardcoded-secret', 'jwt-hardcoded-secret': 'hardcoded-secret', 'flask-hardcoded-secret-key': 'hardcoded-secret',
  'env-not-ignored': 'secret-committed',
  'supabase-service-role': 'client-secret-exposure', 'next-public-secret': 'client-secret-exposure',
  'cors-wildcard': 'cors', 'cors-wildcard-live': 'cors',
  'tls-verification-disabled': 'tls-disabled', 'py-requests-noverify': 'tls-disabled',
  'debug-enabled': 'debug-mode', 'py-flask-debug': 'debug-mode',
  'rls-not-enabled': 'rls-missing', 'rls-disabled': 'rls-missing', 'rls-no-policy': 'rls-missing',
  'rls-permissive-policy': 'rls-permissive',
  'weak-hash': 'weak-password-hash', 'py-weak-hash': 'weak-password-hash',
  'jwt-none-alg': 'jwt-misconfig', 'py-jwt-none': 'jwt-misconfig', 'jwt-not-verified': 'jwt-misconfig',
  'privilege-escalation': 'mass-assignment',
  'insecure-cookie': 'insecure-cookie',
};

/** Ordered keyword rules over (check_id + message + CWE tags) for Semgrep. First match wins. */
export const SEMGREP_RULES: Array<[IssueClass, RegExp]> = [
  ['sqli', /\bcwe-89\b|sql-?injection|tainted-sql|sqlalchemy-execute-raw|formatted-sql|sql-string|raw-query|sequelize-raw|prisma-raw/i],
  ['nosql-injection', /\bcwe-943\b|nosql|mongo.*inject|mongoose.*inject/i],
  ['hardcoded-secret', /\bcwe-798\b|\bcwe-321\b|hardcoded-(jwt|secret|token|password)|jwt-.*(hardcode|secret)|secret-key|detected-.*(key|token|secret)|generic\.secrets|hardcoded/i],
  ['cors', /\bcwe-942\b|cors|access-control-allow-origin/i],
  ['tls-disabled', /\bcwe-295\b|\bcwe-599\b|verify-?false|disabled-cert|reject-?unauthorized|certificate-validation|ssl-verify|requests-.*verify|tls-reject/i],
  ['debug-mode', /\bcwe-489\b|\bcwe-215\b|debug-enabled|flask.*debug|app-run-debug/i],
  ['unsafe-deserialization', /\bcwe-502\b|pickle|yaml\.load|yaml-load|insecure-deserial|unsafe-deserial|avoid-pickle|avoid-yaml/i],
  ['code-injection', /\bcwe-95\b|eval-detected|eval-injection|exec-detected|code-injection|dangerous-eval|dangerous-exec|avoid-eval/i],
  ['command-injection', /\bcwe-78\b|command-injection|shell-injection|subprocess-injection|dangerous-subprocess|child-process|exec-injection|os-system|shell=true|subprocess-shell-true/i],
  ['path-traversal', /\bcwe-22\b|path-traversal|send-file|sendfile|path-join-resolve|directory-traversal/i],
  ['xss', /\bcwe-79\b|\bxss\b|dangerouslysetinnerhtml|innerhtml|cross-site-scripting/i],
  ['ssrf', /\bcwe-918\b|ssrf|server-side-request/i],
  ['open-redirect', /\bcwe-601\b|open-redirect|unvalidated-redirect|redirect/i],
  ['weak-password-hash', /\bcwe-327\b|\bcwe-328\b|\bcwe-916\b|md5|sha1|insecure-hash|weak-hash|weak-crypto|insecure-crypto/i],
  ['jwt-misconfig', /jwt-decode|jwt.*(without-verify|no-verify|none-alg|unverified)|unverified-jwt|\bcwe-345\b|\bcwe-347\b/i],
  ['mass-assignment', /\bcwe-915\b|mass-assign/i],
  ['insecure-cookie', /\bcwe-614\b|\bcwe-1004\b|\bcwe-1275\b|cookie|httponly|secure-flag|samesite/i],
  ['webhook-signature-missing', /webhook|signature-verif/i],
  ['firebase-open-rules', /firebase|firestore/i],
  ['idor', /\bcwe-639\b|\bidor\b|insecure-direct-object|missing-ownership/i],
  ['missing-auth', /\bcwe-306\b|\bcwe-862\b|\bcwe-285\b|missing-auth|unauthenticated|no-auth/i],
  ['client-secret-exposure', /service[-_]?role|next-public|public-env-secret/i],
];

/** Keyword rules over the free-text `issue` of an LLM JSON line. A line may map to several classes. */
export const LLM_RULES: Array<[IssueClass, RegExp]> = [
  ['sqli', /sql.?inject|string concat.*(sql|quer)|(sql|quer).*(concatenat|interpolat|f-string|template)|raw sql|queryRawUnsafe/i],
  ['nosql-injection', /nosql|no-sql|mongo[^.]{0,40}inject|operator injection|\$ne|\$gt/i],
  ['command-injection', /command injection|shell injection|shell=true|os command|arbitrary command|subprocess[^.]{0,50}(user|shell|inject|unsanit)/i],
  ['code-injection', /\beval\b|code injection|remote code execution|arbitrary code (execution|exec)/i],
  ['unsafe-deserialization', /pickle|yaml\.load|unsafe yaml|insecure deserializ|unsafe deserializ|deserialization/i],
  ['path-traversal', /path traversal|directory traversal|\.\.\/|arbitrary file (read|access|download)|local file (read|inclusion)/i],
  ['xss', /\bxss\b|cross-site scripting|dangerouslysetinnerhtml|innerhtml/i],
  ['ssrf', /\bssrf\b|server-side request forgery/i],
  ['open-redirect', /open redirect|unvalidated redirect|redirect[^.]{0,40}(unvalidated|arbitrary|untrusted|user-controlled|any url)/i],
  ['missing-auth', /(no|missing|lack|without|absent)[^.]{0,40}(authentication|authorization|access control|auth check|auth middleware)|unauthenticated|unprotected (route|endpoint|admin)|not (protected|authenticated)|anyone can (delete|call|access)/i],
  ['idor', /\bidor\b|insecure direct object|(no|missing|without|lack)[^.]{0,40}(ownership|owner check|tenant|org(anization)? (id|filter|scop))|any (authenticated )?user can (read|view|access|modify|update|delete)[^.]{0,40}(other|any|another)|broken object|cross-tenant|tenant isolation|all (tenants|organi[sz]ations)/i],
  ['hardcoded-secret', /hard-?coded[^.]{0,40}(secret|key|jwt|token|password|credential)|(secret|key|jwt|token|password|credential)s?[^.]{0,30}hard-?coded|secret[^.]{0,20}(in source|in code|literal)/i],
  ['secret-committed', /\.env[^.]{0,60}(committed|checked in|in version control|is tracked|not (git)?ignored)|(no|missing|without|absent)[^.]{0,20}\.git.?ignore|secrets? (committed|checked in)/i],
  ['client-secret-exposure', /service[-_ ]?role[^.]{0,80}(next_public|public|browser|client|frontend|bundle|exposed)|(next_public|browser|client|frontend|exposed)[^.]{0,80}(service[-_ ]?role|secret|api key|openai)|dangerouslyallowbrowser/i],
  ['cors', /\bcors\b|access-control-allow-origin|cross-origin resource/i],
  ['tls-disabled', /(certificate|cert|tls|ssl)[^.]{0,40}(verification|validation)[^.]{0,30}(disabled|off|bypass|skipped)|(disabled|disables|bypass|skip)[^.]{0,30}(certificate|cert|tls|ssl)|verify\s*=\s*false|rejectunauthorized\s*:?\s*false|reject_unauthorized/i],
  ['debug-mode', /debug[^.]{0,30}(mode|true|enabled|on)|(werkzeug|flask) debug|debug=true/i],
  ['rls-permissive', /using\s*\(\s*true\s*\)|with check\s*\(\s*true\s*\)|permissive (rls )?polic|policy[^.]{0,40}(true|allow(s)? (all|any|everyone))|(always|unconditionally) true/i],
  ['rls-missing', /(rls|row[- ]level security)[^.]{0,40}(not (been )?enabled|is disabled|never enabled|missing)|(no|without|missing|never|lack of)\s+['"`]?(rls|row[- ]level security|enable row level)|(did not|does not|doesn't|never|not) enable[^.]{0,20}(rls|row[- ]level)/i],
  ['firebase-open-rules', /(firestore|firebase|storage)[^.]{0,60}(rules?)[^.]{0,60}(open|allow(s)? (all|any|everyone)|if true|public|wide)|allow read, write: if true/i],
  ['webhook-signature-missing', /webhook[^.]{0,80}(signature|verif|authenticat|spoof|forg)|(signature|verif)[^.]{0,60}webhook|constructEvent/i],
  ['weak-password-hash', /\bmd5\b|\bsha-?1\b|weak (password )?hash|unsalted|insecure hash/i],
  ['jwt-misconfig', /jwt[^.]{0,60}(decode|not verified|unverified|without verif|signature|none)|(decode|unverified)[^.]{0,40}jwt|algorithm[^.]{0,20}none/i],
  ['mass-assignment', /mass[- ]assign|req\.body[^.]{0,60}(directly|entire|whole|unfiltered)|(directly|entire|whole)[^.]{0,30}req\.body|privilege escalation[^.]{0,40}(isadmin|role)|overposting/i],
  ['insecure-cookie', /cookie[^.]{0,60}(httponly|secure|samesite|insecure)|(httponly|secure flag|samesite)[^.]{0,40}(false|missing|not set|disabled)/i],
];
