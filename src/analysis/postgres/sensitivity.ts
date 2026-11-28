/**
 * How sensitive is a table's data? Decides the severity of an unrestricted read.
 *
 * Precedence: project config (`sensitiveTables`, then `publicTables`) > sensitive name >
 * public-by-name (content tables such as posts only with a `published`-style column) >
 * a per-user / per-tenant column (`user_id`, `org_id`, ... plus `tenantColumns`) > unknown.
 */
import type { TableState } from './model';

export interface RlsProjectConfig {
  /** Tables whose rows are meant to be world-readable (`name` or `schema.name`). */
  publicTables?: string[];
  /** Tables that hold private data regardless of their name. */
  sensitiveTables?: string[];
  /** Extra column names that scope a row to a user / tenant (added to the built-in list). */
  tenantColumns?: string[];
  /** Schemas the Data API exposes (default: `public`, `graphql_public`, or supabase/config.toml). */
  exposedSchemas?: string[];
  /** Storage buckets meant to be world-readable (e.g. `avatars`). */
  publicBuckets?: string[];
  /** Storage buckets that hold private files regardless of their name. */
  sensitiveBuckets?: string[];
}

export type Sensitivity = 'sensitive' | 'public' | 'unknown';

export interface SensitivityVerdict {
  level: Sensitivity;
  reason: string;
}

const SENSITIVE_WORDS = new Set([
  'invoice', 'payment', 'payout', 'transaction', 'refund', 'purchase', 'receipt', 'ledger', 'balance', 'billing', 'bill',
  'subscription', 'card', 'bank', 'wallet', 'tax', 'salary', 'payroll', 'order',
  'message', 'chat', 'conversation', 'thread', 'inbox', 'dm', 'note', 'document', 'file', 'attachment', 'upload',
  'profile', 'user', 'account', 'customer', 'client', 'member', 'membership', 'employee', 'contact', 'address', 'email',
  'phone', 'identity', 'kyc', 'ssn', 'passport', 'patient', 'medical', 'health', 'diagnosis', 'prescription',
  'role', 'permission', 'auth', 'session', 'token', 'secret', 'credential', 'password', 'key', 'apikey', 'otp',
  'invite', 'invitation', 'notification', 'audit', 'private', 'personal',
]);
/** Public by name: reference / catalog data. */
const CATALOG_WORDS = new Set(['product', 'catalog', 'catalogue', 'category', 'tag', 'faq', 'country', 'currency', 'language', 'locale', 'timezone', 'sku', 'brand']);
/** Public only when the table has a publish flag. */
const CONTENT_WORDS = new Set(['post', 'article', 'blog', 'page', 'comment', 'story', 'episode', 'event', 'review', 'listing', 'recipe']);
const PUBLISH_COLUMNS = new Set(['published', 'is_published', 'published_at', 'visibility', 'is_public', 'public', 'status']);
const TENANT_COLUMNS = [
  'user_id', 'owner_id', 'created_by', 'account_id', 'customer_id', 'profile_id', 'member_id',
  'org_id', 'organization_id', 'tenant_id', 'team_id', 'workspace_id', 'company_id',
];

export function words(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
    .map(singular);
}

function singular(w: string): string {
  if (w.endsWith('ies') && w.length > 4) return `${w.slice(0, -3)}y`;
  if (/(sses|ches|shes|xes)$/.test(w)) return w.slice(0, -2);
  if (w.endsWith('s') && !w.endsWith('ss') && w.length > 3) return w.slice(0, -1);
  return w;
}

function listed(list: string[] | undefined, t: TableState): boolean {
  if (!list) return false;
  const full = `${t.schema}.${t.name}`.toLowerCase();
  return list.some((x) => {
    const v = x.trim().replace(/"/g, '').toLowerCase();
    return v === full || v === t.name.toLowerCase();
  });
}

export function tenantColumnsOf(t: TableState, cfg: RlsProjectConfig): string[] {
  if (!t.columns) return [];
  const names = new Set([...TENANT_COLUMNS, ...(cfg.tenantColumns ?? []).map((c) => c.toLowerCase())]);
  return [...t.columns].filter((c) => names.has(c.toLowerCase()));
}

export function classifyTable(t: TableState, cfg: RlsProjectConfig): SensitivityVerdict {
  if (listed(cfg.sensitiveTables, t)) return { level: 'sensitive', reason: 'listed in sensitiveTables' };
  if (listed(cfg.publicTables, t)) return { level: 'public', reason: 'listed in publicTables' };
  const ws = words(t.name);
  const hit = ws.find((w) => SENSITIVE_WORDS.has(w));
  if (hit) return { level: 'sensitive', reason: `the name suggests private data ("${hit}")` };
  if (ws.some((w) => CATALOG_WORDS.has(w))) return { level: 'public', reason: 'catalog / reference data by name' };
  if (ws.some((w) => CONTENT_WORDS.has(w)) && t.columns && [...t.columns].some((c) => PUBLISH_COLUMNS.has(c.toLowerCase()))) {
    return { level: 'public', reason: 'published content (has a publish flag)' };
  }
  const tenant = tenantColumnsOf(t, cfg);
  if (tenant.length) return { level: 'sensitive', reason: `rows belong to a user or tenant (${tenant.join(', ')})` };
  return { level: 'unknown', reason: 'sensitivity unknown' };
}

/** Bucket names that are normally public: profile pictures, site assets. */
const PUBLIC_BUCKET_WORDS = new Set([
  'avatar', 'public', 'image', 'img', 'asset', 'media', 'logo', 'banner', 'thumbnail', 'thumb', 'icon', 'static', 'cover',
  'gallery', 'product', 'cdn', 'font', 'emoji', 'sticker', 'og', 'website', 'site', 'marketing', 'blog', 'post',
]);
const SENSITIVE_BUCKET_WORDS = new Set([
  ...SENSITIVE_WORDS, 'secure', 'kyc', 'id', 'contract', 'statement', 'backup', 'export', 'recording', 'voice', 'resume', 'cv',
  'scan', 'payslip', 'report', 'confidential', 'internal', 'legal', 'license', 'verification', 'evidence', 'claim',
]);

export function classifyBucket(id: string, cfg: RlsProjectConfig): SensitivityVerdict {
  const has = (list: string[] | undefined): boolean => Boolean(list?.some((x) => x.trim().toLowerCase() === id.toLowerCase()));
  if (has(cfg.sensitiveBuckets)) return { level: 'sensitive', reason: 'listed in sensitiveBuckets' };
  if (has(cfg.publicBuckets)) return { level: 'public', reason: 'listed in publicBuckets' };
  const ws = words(id);
  const hit = ws.find((w) => SENSITIVE_BUCKET_WORDS.has(w));
  if (hit) return { level: 'sensitive', reason: `the bucket name suggests private files ("${hit}")` };
  if (ws.some((w) => PUBLIC_BUCKET_WORDS.has(w))) return { level: 'public', reason: 'public assets by name' };
  return { level: 'unknown', reason: 'sensitivity unknown' };
}

/** Columns whose value is a credential: never readable by API roles. */
const SECRET_COLUMN_RE =
  /^(?:password|password_hash|passwd|pwd|hashed_password|encrypted_password|secret|.*_secret|token|.*_token|api_key|apikey|.*_api_key|private_key|.*_private_key|otp|otp_code|totp_secret|mfa_secret|recovery_codes?|ssn|social_security_number|tax_id|national_id|card_number|cvv|iban|account_number|routing_number)$/;
/** Personal data: readable by everyone is a privacy leak. */
const PII_COLUMN_RE =
  /^(?:email|email_address|phone|phone_number|mobile|address|street|street_address|postal_code|zip|zip_code|date_of_birth|dob|birthdate|birthday|ip|ip_address|last_ip|full_name|legal_name|salary|income|stripe_customer_id|customer_id)$/;

export function columnSensitivity(col: string): 'secret' | 'pii' | null {
  const c = col.toLowerCase();
  if (SECRET_COLUMN_RE.test(c)) return 'secret';
  if (PII_COLUMN_RE.test(c)) return 'pii';
  return null;
}
