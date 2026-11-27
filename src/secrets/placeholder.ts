/**
 * Placeholder / non-literal value classification, shared by detection and redaction.
 *
 * Rule: a value is a placeholder only when the WHOLE value is a clear placeholder
 * (`changeme`, `your-key-here`, `<token>`, `xxxx`, `${VAR}`, `process.env.X`, empty, …).
 * A value that merely STARTS with test/demo/example/sample (`test-Xy9!real…`) is a
 * real-looking value and is treated as a secret.
 */

const WHOLE_PLACEHOLDER_RE = new RegExp(
  '^(?:' +
    [
      'change[-_ ]?me(?:[-_ ]?(?:please|now|later))?',
      'change[-_ ]?this',
      'placeholder',
      'example',
      'sample',
      'test',
      'testing',
      'demo',
      'dummy',
      'fake',
      'secret',
      'password',
      'passwd',
      'pass',
      'pwd',
      'token',
      'apikey',
      'api[-_ ]?key',
      'key',
      'value',
      'todo',
      'tbd',
      'fixme',
      'none',
      'null',
      'nil',
      'undefined',
      'empty',
      'redacted',
      'hidden',
      'secret[-_ ]?here',
      'insert[-_ ][\\w -]{0,40}',
      'enter[-_ ][\\w -]{0,40}',
      'replace[-_ ][\\w -]{0,40}',
      'your[-_ .]?[\\w .-]{0,60}',
      'my[-_ ]?(?:secret|password|token|api[-_ ]?key|key)(?:[-_ ]?here)?',
      '[\\w-]{0,30}[-_ ]here',
      'x{3,}',
      '\\*{3,}',
      '•{3,}',
      '\\.{3,}',
      '…',
      '-+',
      '_+',
      '0+',
    ].join('|') +
    ')$',
  'i',
);

/** Template / env-reference shapes that are not literal values. */
const REFERENCE_RE =
  /^(?:\$\{[^}]{0,200}\}|\$\{\{[^}]{0,200}\}\}|\{\{[^}]{0,200}\}\}|\$[A-Za-z_][A-Za-z0-9_]*|%\(?[A-Za-z_][A-Za-z0-9_]*\)?s?%?|<[^<>]{0,100}>|\[[A-Z_ ]{2,60}\]|(?:process\.env|import\.meta\.env|os\.environ|os\.getenv|getenv|env)\b[\w.[\]('"]*\)?|\$\(\s*[\w ./-]{1,100}\))$/;

/** True when the whole value is a clear placeholder or an env/template reference, not a literal secret. */
export function isPlaceholder(raw: string): boolean {
  const v = (raw ?? '').trim();
  if (v === '') return true;
  if (v.includes('«REDACTED')) return true;
  if (WHOLE_PLACEHOLDER_RE.test(v)) return true;
  if (REFERENCE_RE.test(v)) return true;
  // Mostly masking characters: "sk-xxxxxxxxxxxx", "AKIA************", "ghp_XXXXXXXX".
  const masked = (v.match(/[xX*•]/g) ?? []).length;
  if (v.length >= 6 && masked / v.length >= 0.6) return true;
  // "sk-...", "eyJ...": a short prefix followed by an ellipsis.
  if (v.length <= 24 && /(?:\.{3}|…)$/.test(v)) return true;
  return false;
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Secret-NAMED keys (variable, property, header, env, YAML/TOML/JSON keys).
 * `auth` alone, `key` alone and `author`-like names are deliberately not secret names.
 */
const SECRET_KEY_RE =
  /(?:secret|passw(?:or)?d|passwd|passphrase|(?:^|[^a-z])pwd(?:$|[^a-z])|(?:^|[_.-])pass(?:$|[_.-])|api[_-]?key|apikey|access[_-]?key|private[_-]?key|signing[_-]?key|encryption[_-]?key|master[_-]?key|session[_-]?key|auth[_-]?key|client[_-]?secret|credential|token|authorization|(?:^|[_.-])auth$|cookie|conn(?:ection)?[_-]?str(?:ing)?|(?:database|db|redis|mongo(?:db)?|amqp|rabbitmq)[_-]?(?:url|uri|dsn)|^dsn$)/i;

/** Names that contain a secret word but describe metadata about it, not the secret itself. */
const NON_SECRET_KEY_RE =
  /(?:^|[_.-])(?:url|uri|endpoint|type|name|field|label|length|len|count|limit|max|min|ttl|path|file|filename|header|prefix|hint|policy|rules?|regex|pattern|schema|placeholder|expires?(?:_?in|_?at)?|expiry|lifetime|duration|timeout|storage|mode|strategy|provider|format|algorithm|alg|version|enabled|required|visible|input|location|source|kind)$|^(?:max|num|n|total|input|output|prompt|completion)_?tokens?$|tokeniz|(?:Url|Uri|Endpoint|Type|Name|Field|Label|Length|Count|Limit|Ttl|Path|File|Header|Prefix|Hint|Policy|Schema|Placeholder|ExpiresIn|ExpiresAt|Expiry|Timeout|Storage|Mode|Strategy|Provider|Format|Algorithm|Version|Enabled|Required|Visible|Input|Location|Source|Kind)$/;

/** URL-shaped DB/queue keys hold a URL whose credentials the URL detector judges separately. */
export function isSecretKey(key: string): boolean {
  const k = key.replace(/^["'`$@]+|["'`]+$/g, '');
  if (!SECRET_KEY_RE.test(k)) return false;
  if (/(?:database|db|redis|mongo(?:db)?|amqp|rabbitmq)[_-]?(?:url|uri|dsn)$|^dsn$|conn(?:ection)?[_-]?str/i.test(k)) return true;
  return !NON_SECRET_KEY_RE.test(k);
}

/** Password-type keys: any non-placeholder literal is sensitive, even a plain word. */
export function isPasswordKey(key: string): boolean {
  return /passw(?:or)?d|passwd|passphrase|(?:^|[^a-z])pwd(?:$|[^a-z])|(?:^|[_.-])pass$|secret/i.test(key);
}

/** Unquoted values that are code, types or keywords rather than literal data. */
export function isCodeLike(v: string): boolean {
  return (
    /^[A-Za-z_$][\w$]*(?:\??\.[\w$]|\[|\(|::)/.test(v) ||
    /^(?:true|false|null|nil|none|None|undefined|this|self|new|await|require|import|function|async|return|typeof|void|yield|lambda|def|fn|string|number|boolean|bool|str|int|float|bytes|any|unknown|object|Optional|String|Number|Boolean)$/.test(v) ||
    /^[([{!&|?<>=+*/%-]/.test(v)
  );
}

/** Config words / numbers / URLs a secret-named key often holds that are not secrets (detection only). */
export function isBenignConfigValue(v: string): boolean {
  return (
    /^(?:true|false|null|undefined|none|default|enabled?|disabled?|on|off|yes|no|development|dev|production|prod|staging|local(?:host)?|debug|info|warn(?:ing)?|error|trace|verbose|required|optional|bearer|basic|jwt|oauth2?|header|cookie|query|body|session|memory|redis|localstorage|sessionstorage)$/i.test(v) ||
    /^\d[\d._-]*$/.test(v) ||
    /^https?:\/\/[^\s:@/]+(?:[/:?#][^\s@]*)?$/.test(v) ||
    /^(?:\.{0,2}\/|~\/)[\w./-]+$/.test(v)
  );
}
