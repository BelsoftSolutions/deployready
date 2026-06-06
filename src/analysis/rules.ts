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
    re: /f["'][^"'\n]{0,200}\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]{0,200}\{/i,
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
];

/** Language-agnostic rules (apply to every file). */
const GENERIC_RULES: LineRule[] = [
  {
    rule: 'sql-injection',
    title: 'SQL query built by string concatenation (SQL injection)',
    severity: 'critical',
    category: 'security',
    re: /(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,200}(?:\$\{|"\s*\+|'\s*\+|`\s*\+)/i,
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
];

export const LINE_RULES: LineRule[] = [...JS_RULES, ...PY_RULES, ...GENERIC_RULES];
