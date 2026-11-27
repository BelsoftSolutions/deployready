/**
 * Static security rule definitions. Each rule is a bounded, single-line regex
 * mapped to OWASP Top 10 (2025) and CWE. These encode the exact failure modes
 * research shows AI-generated code produces most: secrets, XSS, injection,
 * permissive CORS, weak crypto, and log injection.
 *
 * Rules are language-scoped via `exts` so JS patterns don't fire on Python and
 * vice-versa. Rules with no `exts` apply to every file.
 *
 * Keep every pattern anchored/bounded — no nested quantifiers — to avoid ReDoS,
 * since we run them over untrusted source files.
 */
import type { Category, Severity } from '../types';

export interface LineRule {
  rule: string;
  title: string;
  severity: Severity;
  category: Category;
  /** The detection pattern. `null` disables the rule (kept for provenance). */
  re: RegExp | null;
  /** File extensions this rule applies to. Omit to apply to all files. */
  exts?: string[];
  owasp?: string;
  cwe?: string;
  recommendation: string;
  /** If set, the matching line is treated as evidence (will be redacted). */
  evidence?: boolean;
  /**
   * Evaluate before generic secret detection and suppress it for the line, so a
   * more specific finding replaces the generic "hardcoded secret" one.
   */
  beforeSecrets?: boolean;
  /** Suppress a regex hit using context the single-line pattern cannot see (whole file, path). */
  skip?: (ctx: { relPath: string; source: string; line: string }) => boolean;
}

/** True when a module can only run on the server (never bundled for the browser). */
export function isServerOnlyModule(relPath: string, source: string): boolean {
  if (/^\s*(?:['"]use client['"]|['"]use client['"];)/m.test(source)) return false;
  if (/\bimport\s+['"]server-only['"]|\brequire\(\s*['"]server-only['"]\s*\)/.test(source)) return true;
  if (/\.py$/i.test(relPath)) return true;
  return (
    /(^|\/)(?:pages\/api|app\/api|supabase\/functions|server|scripts|backend)\//.test(relPath) ||
    /(?:^|\/)(?:route|middleware)\.[jt]sx?$|\.server\.[jt]sx?$/.test(relPath)
  );
}

const JS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
const PY = ['.py'];

/** JavaScript / TypeScript rules. */
const JS_RULES: LineRule[] = [
  {
    rule: 'eval-usage',
    title: 'Use of eval() / new Function() (code injection risk)',
    severity: 'critical',
    category: 'security',
    re: /\b(?:eval|new\s+Function)\s*\(/,
    exts: JS,
    evidence: true,
    owasp: 'A05:2025',
    cwe: 'CWE-95',
    recommendation:
      'Remove eval()/new Function(). Parse JSON with JSON.parse and replace dynamic code execution with explicit logic.',
  },
  {
    rule: 'command-injection',
    title: 'Shell command built from variables (command injection)',
    severity: 'critical',
    category: 'security',
    re: /\b(?:exec|execSync|spawnSync)\s*\(\s*[`'"][^`'"]*\$\{/,
    exts: JS,
    owasp: 'A05:2025',
    cwe: 'CWE-78',
    recommendation:
      'Never interpolate input into a shell string. Use execFile/spawn with an argument array, and validate inputs against an allowlist.',
    evidence: true,
  },
  {
    rule: 'xss-sink',
    title: 'Unsafe HTML sink (cross-site scripting)',
    severity: 'critical',
    category: 'security',
    re: /\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write)\b/,
    exts: JS,
    owasp: 'A05:2025',
    cwe: 'CWE-79',
    recommendation:
      'Avoid raw HTML sinks. Use textContent, framework-escaped rendering, or sanitize with DOMPurify before inserting user data.',
  },
  {
    rule: 'cors-wildcard',
    title: 'CORS configured to allow any origin (*)',
    severity: 'warning',
    category: 'security',
    re: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*|cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*/,
    exts: JS,
    owasp: 'A02:2025',
    cwe: 'CWE-942',
    recommendation:
      'Restrict CORS to an explicit allowlist of trusted origins instead of "*", especially for credentialed requests.',
  },
  {
    rule: 'tls-verification-disabled',
    title: 'TLS certificate verification disabled',
    severity: 'critical',
    category: 'security',
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/,
    exts: JS,
    owasp: 'A04:2025',
    cwe: 'CWE-295',
    recommendation:
      'Never disable certificate validation. Fix the underlying trust chain instead of setting rejectUnauthorized:false.',
  },
  {
    rule: 'weak-hash',
    title: 'Weak hash algorithm (MD5/SHA1)',
    severity: 'warning',
    category: 'security',
    re: /createHash\s*\(\s*['"](?:md5|sha1)['"]/i,
    exts: JS,
    owasp: 'A04:2025',
    cwe: 'CWE-327',
    recommendation:
      'Use SHA-256+ for integrity and a slow KDF (bcrypt/scrypt/argon2) for passwords — never MD5/SHA1.',
  },
  {
    rule: 'insecure-random',
    title: 'Math.random() used for security-sensitive value',
    severity: 'warning',
    category: 'security',
    re: /(?:token|secret|otp|nonce|salt|password)\s*=\s*[^;\n]{0,60}Math\.random\s*\(/i,
    exts: JS,
    owasp: 'A04:2025',
    cwe: 'CWE-338',
    recommendation:
      'Use crypto.randomBytes / crypto.randomUUID for tokens, salts, and nonces — Math.random() is predictable.',
  },
  {
    rule: 'log-injection',
    title: 'User input logged without sanitization (log injection)',
    severity: 'info',
    category: 'security',
    re: /console\.(?:log|error|info)\s*\([^)]*\breq\.(?:body|query|params|headers)/,
    exts: JS,
    owasp: 'A09:2025',
    cwe: 'CWE-117',
    recommendation:
      'Sanitize/encode user-controlled values before logging, or log structured fields so injected newlines cannot forge log entries.',
  },
  {
    rule: 'jwt-none-alg',
    title: 'JWT configured with the "none" algorithm (signature bypass)',
    severity: 'critical',
    category: 'security',
    re: /algorithms?\s*:\s*\[?\s*['"]none['"]/i,
    exts: JS,
    owasp: 'A02:2025',
    cwe: 'CWE-347',
    recommendation:
      'Never accept the "none" JWT algorithm — it disables signature verification. Pin a strong algorithm (RS256/HS256) and verify signatures.',
  },
  {
    rule: 'jwt-hardcoded-secret',
    title: 'JWT signed/verified with a hardcoded secret (anyone can forge login tokens)',
    severity: 'critical',
    category: 'security',
    // jwt.sign(payload, 'literal') / jsonwebtoken.verify(t, "literal") / jose with TextEncoder|Buffer of a literal.
    re: new RegExp(
      [
        `\\b(?:jwt|jsonwebtoken)\\.(?:sign|verify)\\s*\\((?:[^\\n\\[\\]]|\\[[^\\]'"\`\\n]*\\]){0,300}?,\\s*(["'\`])(?![^"'\`\\n]*\\$\\{)[^"'\`\\n]{3,}\\1\\s*[,)]`,
        `\\.sign\\s*\\(\\s*(?:new\\s+TextEncoder\\s*\\(\\s*\\)\\s*\\.encode|Buffer\\.from)\\s*\\(\\s*(["'\`])(?![^"'\`\\n]*\\$\\{)[^"'\`\\n]{3,}\\2`,
        `\\bjwtVerify\\s*\\([^\\n\\[\\]]{0,200}?,\\s*(?:new\\s+TextEncoder\\s*\\(\\s*\\)\\s*\\.encode|Buffer\\.from)\\s*\\(\\s*(["'\`])(?![^"'\`\\n]*\\$\\{)[^"'\`\\n]{3,}\\3`,
      ].join('|'),
    ),
    exts: JS,
    beforeSecrets: true,
    owasp: 'A02:2025',
    cwe: 'CWE-798',
    recommendation:
      'Anyone who reads this code (or the bundle, repo or a leaked copy) can mint valid login tokens for any user. Load the signing secret from an environment variable or secret manager, use a long random value, and rotate it now — all tokens signed with the old one must be treated as forgeable.',
  },
  {
    rule: 'insecure-cookie',
    title: 'Cookie set with httpOnly disabled',
    severity: 'warning',
    category: 'security',
    re: /httpOnly\s*:\s*false/i,
    exts: JS,
    owasp: 'A05:2025',
    cwe: 'CWE-1004',
    recommendation:
      'Set httpOnly:true on session/auth cookies so client-side JS cannot read them, plus secure:true and an appropriate sameSite.',
  },
];

/** Python rules. */
const PY_RULES: LineRule[] = [
  {
    rule: 'py-eval-exec',
    title: 'Use of eval()/exec() (code injection risk)',
    severity: 'critical',
    category: 'security',
    re: /\b(?:eval|exec)\s*\(/,
    exts: PY,
    owasp: 'A05:2025',
    cwe: 'CWE-95',
    recommendation: 'Avoid eval()/exec(). Parse data with ast.literal_eval or json.loads and use explicit logic.',
    evidence: true,
  },
  {
    rule: 'py-shell-injection',
    title: 'subprocess with shell=True (command injection)',
    severity: 'critical',
    category: 'security',
    re: /subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]{0,200}shell\s*=\s*True/,
    exts: PY,
    owasp: 'A05:2025',
    cwe: 'CWE-78',
    recommendation: 'Use subprocess with shell=False and an argument list; never pass a built command string to a shell.',
    evidence: true,
  },
  {
    rule: 'py-os-system',
    title: 'os.system() with a built command (command injection)',
    severity: 'critical',
    category: 'security',
    re: /\bos\.(?:system|popen)\s*\([^)]{0,200}(?:\+|%|\.format\(|f["'])/,
    exts: PY,
    owasp: 'A05:2025',
    cwe: 'CWE-78',
    recommendation: 'Replace os.system with subprocess and an argument list; validate inputs against an allowlist.',
    evidence: true,
  },
  {
    rule: 'py-sql-fstring',
    title: 'SQL built with an f-string / format (SQL injection)',
    severity: 'critical',
    category: 'security',
    re: new RegExp(
      ['"', "'"]
        .flatMap((q) => {
          const stmt = `[^${q}\\n]{0,200}\\b(?:select\\b[^${q}\\n]{0,200}\\bfrom|insert\\s+into|update\\s+\\S+\\s+set|delete\\s+from)\\b[^${q}\\n]{0,200}`;
          return [
            // f"... {x}"
            `\\bf${q}${stmt}\\{`,
            // "...".format(x) / "... %s" % x
            `${q}${stmt}${q}\\s*(?:\\.format\\s*\\(|%\\s*[\\w(])`,
          ];
        })
        .join('|'),
      'i',
    ),
    exts: PY,
    owasp: 'A05:2025',
    cwe: 'CWE-89',
    recommendation: 'Use parameterized queries (cursor.execute(sql, params)) instead of building SQL with f-strings/format.',
    evidence: true,
  },
  {
    rule: 'py-yaml-load',
    title: 'yaml.load without SafeLoader (unsafe deserialization)',
    severity: 'critical',
    category: 'security',
    re: /\byaml\.load\s*\((?![^)\n]{0,120}(?:SafeLoader|Loader\s*=\s*yaml\.SafeLoader))/,
    exts: PY,
    owasp: 'A08:2025',
    cwe: 'CWE-502',
    recommendation: 'Use yaml.safe_load() (or Loader=yaml.SafeLoader). yaml.load can execute arbitrary objects.',
  },
  {
    rule: 'py-pickle-loads',
    title: 'Unpickling untrusted data (deserialization risk)',
    severity: 'warning',
    category: 'security',
    re: /\bpickle\.loads?\s*\(/,
    exts: PY,
    owasp: 'A08:2025',
    cwe: 'CWE-502',
    recommendation: 'Never unpickle untrusted data — it can execute code. Use JSON or a signed/safe format.',
  },
  {
    rule: 'py-requests-noverify',
    title: 'TLS verification disabled (verify=False)',
    severity: 'critical',
    category: 'security',
    re: /\bverify\s*=\s*False\b/,
    exts: PY,
    owasp: 'A04:2025',
    cwe: 'CWE-295',
    recommendation: 'Do not set verify=False on requests; fix the certificate trust chain instead.',
  },
  {
    rule: 'py-flask-debug',
    title: 'Flask debug mode enabled (app.run(debug=True))',
    severity: 'warning',
    category: 'config',
    re: /\.run\s*\([^)]{0,160}debug\s*=\s*True/,
    exts: PY,
    owasp: 'A02:2025',
    cwe: 'CWE-489',
    recommendation: 'Never run with debug=True in production — it exposes the Werkzeug debugger (RCE) and stack traces.',
  },
  {
    rule: 'py-weak-hash',
    title: 'Weak hash algorithm (hashlib.md5/sha1)',
    severity: 'warning',
    category: 'security',
    re: /hashlib\.(?:md5|sha1)\s*\(/,
    exts: PY,
    owasp: 'A04:2025',
    cwe: 'CWE-327',
    recommendation: 'Use hashlib.sha256+ for integrity and bcrypt/argon2/scrypt for passwords — never MD5/SHA1.',
  },
  {
    rule: 'py-insecure-random',
    title: 'random module used for a security-sensitive value',
    severity: 'warning',
    category: 'security',
    re: /(?:token|secret|otp|nonce|salt|password|key)\s*=\s*[^\n]{0,80}\brandom\.(?:random|randint|choice|getrandbits|randrange)\s*\(/i,
    exts: PY,
    owasp: 'A04:2025',
    cwe: 'CWE-338',
    recommendation: 'Use the secrets module (secrets.token_hex / token_urlsafe) for tokens, salts, and nonces.',
  },
  {
    rule: 'py-mktemp',
    title: 'Insecure temp file via tempfile.mktemp() (race condition)',
    severity: 'warning',
    category: 'security',
    re: /\btempfile\.mktemp\s*\(/,
    exts: PY,
    owasp: 'A04:2025',
    cwe: 'CWE-377',
    recommendation: 'Use tempfile.mkstemp() or NamedTemporaryFile() — mktemp() is vulnerable to a TOCTOU race.',
  },
  {
    rule: 'jwt-hardcoded-secret',
    title: 'JWT signed/verified with a hardcoded secret (anyone can forge login tokens)',
    severity: 'critical',
    category: 'security',
    // jwt.encode(payload, "literal", ...) / jwt.decode(t, key="literal", ...) — plain string literals only (not f-strings).
    re: /\bjwt\.(?:encode|decode)\s*\([^\n[\]]{0,300}?,\s*(?:key\s*=\s*)?(["'])[^"'\n]{3,}\1\s*[,)]/,
    exts: PY,
    beforeSecrets: true,
    owasp: 'A02:2025',
    cwe: 'CWE-798',
    recommendation:
      'Anyone who reads this code can mint valid login tokens for any user. Load the signing key from an environment variable or secret manager (os.environ), use a long random value, and rotate it now — tokens signed with the old key must be treated as forgeable.',
  },
  {
    rule: 'flask-hardcoded-secret-key',
    title: 'Hardcoded Flask/Django SECRET_KEY (anyone can forge sessions)',
    severity: 'critical',
    category: 'security',
    re: /(?:\.secret_key|\[\s*["']SECRET_KEY["']\s*\]|\bSECRET_KEY)\s*=\s*(["'])(?!(?:change[-_ ]?me|your[-_]|<|x{3,}|placeholder)[^"'\n]*\1)[^"'\n]{3,}\1/,
    exts: PY,
    beforeSecrets: true,
    owasp: 'A02:2025',
    cwe: 'CWE-798',
    recommendation:
      'The session-signing key is in source, so anyone who sees the code can forge session cookies and log in as any user. Load it from an environment variable or secret manager, use a long random value, and rotate it now.',
  },
  {
    rule: 'py-jwt-none',
    title: 'JWT configured with the "none" algorithm (signature bypass)',
    severity: 'critical',
    category: 'security',
    re: /algorithms?\s*=\s*\[?\s*['"]none['"]/i,
    exts: PY,
    owasp: 'A02:2025',
    cwe: 'CWE-347',
    recommendation: 'Reject the "none" algorithm; require a strong algorithm and verify signatures (PyJWT: algorithms=["RS256"]).',
  },
];

// A real statement shape (second keyword required), never a bare SELECT/UPDATE word.
const SQL_SHAPE =
  '(?:select\\b(?=[^;\\n]{0,300}\\bfrom\\b)|insert\\s+into\\b|update\\b(?=[^;\\n]{0,300}\\bset\\b)|delete\\s+from\\b)';
const SQL_SIGNAL = '(?:\\$\\{|["\'`]\\s*\\+)';
const SQL_CALL = '(?:\\.(?:query|execute|raw)|\\$?(?:query|execute)RawUnsafe)\\s*(?:<[^>;\\n]{0,60}>)?\\s*\\(';
const SQL_INJECTION_RE = new RegExp(
  [
    // string/template literal that STARTS with a statement, then interpolation/concatenation
    `["'\`]\\s*${SQL_SHAPE}[^;\\n]{0,200}?${SQL_SIGNAL}`,
    // DB call whose literal argument contains a statement anywhere
    `${SQL_CALL}\\s*["'\`][^;\\n]{0,200}?\\b${SQL_SHAPE}[^;\\n]{0,200}?${SQL_SIGNAL}`,
    // continuation line of a multi-line template literal
    `^\\s*(?:select\\b(?=[^;\\n]{0,300}\\bfrom\\b)|insert\\s+into\\b|update\\s+[\\w."\`\\[\\]]+\\s+set\\b|delete\\s+from\\b)[^;\\n]{0,200}?\\$\\{`,
  ].join('|'),
  'i',
);

const PARAMETERIZED_CALL_RE = /\.(?:query|execute|raw|\w+Unsafe)\s*(?:<[^>;\n]{0,60}>)?\s*\(\s*(?:'[^'\n]*'|"[^"\n]*")\s*,/;

/** Env var names that a bundler inlines into client code. */
const CLIENT_ENV_RE = /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*/;
const SECRET_WORD = '(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD|ACCESS_TOKEN|AUTH_TOKEN)';
const SECRET_VENDOR = '(?:OPENAI|ANTHROPIC|STRIPE|SENDGRID|TWILIO|RESEND|MAILGUN|GROQ|GEMINI|DEEPSEEK|OPENROUTER|REPLICATE|HUGGINGFACE|MISTRAL|COHERE|AWS|GITHUB)';

/** Language-agnostic rules (apply to every file). */
const GENERIC_RULES: LineRule[] = [
  {
    rule: 'sql-injection',
    title: 'SQL query built by string concatenation (SQL injection)',
    severity: 'critical',
    category: 'security',
    re: SQL_INJECTION_RE,
    // db.query('... $1 ...', [`%${x}%`]): the template is a bound parameter, not part of the SQL.
    skip: ({ line }) => PARAMETERIZED_CALL_RE.test(line),
    owasp: 'A05:2025',
    cwe: 'CWE-89',
    recommendation:
      'Use parameterized queries / prepared statements (e.g. db.query(sql, [params])) instead of concatenating values into SQL.',
    evidence: true,
  },
  {
    rule: 'debug-enabled',
    title: 'Debug mode enabled',
    severity: 'warning',
    category: 'config',
    re: /\b(?:app\.debug\s*=\s*True|DEBUG\s*=\s*True|debug\s*:\s*true)\b/,
    owasp: 'A02:2025',
    cwe: 'CWE-489',
    recommendation:
      'Disable debug mode in production — it leaks stack traces and internal details to attackers.',
  },
  {
    rule: 'rls-disabled',
    title: 'Row-Level Security disabled (broken access control)',
    severity: 'critical',
    category: 'security',
    re: /disable\s+row\s+level\s+security/i,
    // In .sql files the migration replay (analysis/rls.ts) reports this from the FINAL state, so a
    // disable that a later migration reverts is not flagged; keep the line rule for SQL in code.
    skip: ({ relPath }) => /\.sql$/i.test(relPath),
    owasp: 'A01:2025',
    cwe: 'CWE-285',
    recommendation:
      'Keep RLS enabled and define policies instead of disabling it — without RLS any authenticated user can read/write every row.',
    evidence: true,
  },
  {
    rule: 'supabase-service-role',
    title: 'Supabase service_role key used in application code (bypasses RLS)',
    severity: 'warning',
    category: 'security',
    re: /service_role/i,
    // Server-only modules (server-only import, API routes, edge functions, Python) are the right place
    // for this key; still flag it if the name is exposed to the client bundle via NEXT_PUBLIC_/VITE_.
    // A .sql file naming the service_role ROLE (`to service_role` in a policy or grant) is not a key.
    skip: ({ relPath, source, line }) => /\.sql$/i.test(relPath) || (!CLIENT_ENV_RE.test(line) && isServerOnlyModule(relPath, source)),
    owasp: 'A01:2025',
    cwe: 'CWE-269',
    recommendation:
      'The service_role key bypasses Row-Level Security. Use it only in trusted server-side code (never in client/browser bundles), and prefer the anon key + RLS policies for user-facing access.',
  },
  {
    rule: 'next-public-secret',
    title: 'Secret exposed to the browser through a NEXT_PUBLIC_/VITE_ environment variable',
    severity: 'critical',
    category: 'security',
    re: new RegExp(
      `\\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*(?:${SECRET_WORD}|${SECRET_VENDOR}_[A-Z0-9_]*(?:API_KEY|KEY|TOKEN))[A-Z0-9_]*`,
    ),
    owasp: 'A02:2025',
    cwe: 'CWE-200',
    recommendation:
      'Variables with a NEXT_PUBLIC_/VITE_/REACT_APP_ prefix are inlined into the public JavaScript bundle, so anyone can read this value. Keep the secret in a server-only variable (no prefix) and call the service from an API route or server action; rotate the exposed key.',
  },
  {
    rule: 'insecure-http-url',
    title: 'Insecure http:// URL (cleartext transport)',
    severity: 'info',
    category: 'security',
    re: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org|schemas?\.)[a-z0-9.-]+/i,
    owasp: 'A02:2025',
    cwe: 'CWE-319',
    recommendation:
      'Use https:// for any non-local endpoint so credentials and data are not sent in cleartext.',
    evidence: true,
  },
];

export const LINE_RULES: LineRule[] = [...JS_RULES, ...PY_RULES, ...GENERIC_RULES];
