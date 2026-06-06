/**
 * Static security rule definitions. Each rule is a bounded, single-line regex
 * mapped to OWASP Top 10 (2025) and CWE. These encode the exact failure modes
 * research shows AI-generated code produces most: secrets, XSS, injection,
 * permissive CORS, weak crypto, and log injection.
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
  re: RegExp;
  owasp?: string;
  cwe?: string;
  recommendation: string;
  /** If set, the matching line is treated as evidence (will be redacted). */
  evidence?: boolean;
}

export const LINE_RULES: LineRule[] = [
  {
    rule: 'eval-usage',
    title: 'Use of eval() / new Function() (code injection risk)',
    severity: 'critical',
    category: 'security',
    re: /\b(?:eval|new\s+Function)\s*\(/,
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
    owasp: 'A05:2025',
    cwe: 'CWE-78',
    recommendation:
      'Never interpolate input into a shell string. Use execFile/spawn with an argument array, and validate inputs against an allowlist.',
    evidence: true,
  },
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
    rule: 'xss-sink',
    title: 'Unsafe HTML sink (cross-site scripting)',
    severity: 'critical',
    category: 'security',
    re: /\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write)\b/,
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
    owasp: 'A09:2025',
    cwe: 'CWE-117',
    recommendation:
      'Sanitize/encode user-controlled values before logging, or log structured fields so injected newlines cannot forge log entries.',
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
