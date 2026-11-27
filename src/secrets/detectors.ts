/**
 * Known secret / credential SHAPES. Each detector is a bounded, single-line regex
 * (no nested quantifiers: ReDoS-safe on long lines) plus an optional validator.
 *
 * `confidence` is the DETECTION tier: `high` means "this shape is a real credential
 * with very high probability" (critical finding); `low` means "probably sensitive".
 * `secret: false` marks public identifiers that share a family with secrets (Supabase
 * publishable keys, Stripe publishable keys, Supabase anon JWTs): they are reported as
 * not-a-secret by detection. Redaction is separate and conservative (see utils/redact).
 */

export type Confidence = 'high' | 'low';

export interface DetectorVerdict {
  confidence: Confidence;
  /** False for public keys (publishable / anon): not a secret. */
  secret: boolean;
  /** Overrides the detector id (e.g. jwt -> supabase-service-role-jwt). */
  id?: string;
}

export interface Detector {
  id: string;
  label: string;
  re: RegExp;
  confidence: Confidence;
  /** Defaults to true. */
  secret?: boolean;
  /** Capture group holding the sensitive part (default: whole match). */
  group?: number;
  /** Refine (or reject with null) a match. */
  validate?: (m: RegExpExecArray) => DetectorVerdict | null;
}

/** Decode a JWT payload without verifying it (classification only). */
export function jwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1]!.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const obj = JSON.parse(json) as unknown;
    return obj && typeof obj === 'object' && !Array.isArray(obj) ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const mixed = (s: string): boolean => /\d/.test(s) && /[a-z]/.test(s) && /[A-Z]/.test(s);

export const DETECTORS: Detector[] = [
  // ---- AI providers ----
  { id: 'anthropic-api-key', label: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,200}/g, confidence: 'high' },
  {
    id: 'openai-api-key',
    label: 'OpenAI API key',
    re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-|None-)?([A-Za-z0-9_-]{20,200})/g,
    confidence: 'high',
    validate: (m) => (mixed(m[1] ?? '') || /T3BlbkFJ/.test(m[0]) ? { confidence: 'high', secret: true } : null),
  },
  // ---- Source hosting ----
  { id: 'github-token', label: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, confidence: 'high' },
  { id: 'github-fine-grained-pat', label: 'GitHub fine-grained PAT', re: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g, confidence: 'high' },
  { id: 'gitlab-token', label: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,64}\b/g, confidence: 'high' },
  // ---- Cloud ----
  { id: 'aws-access-key-id', label: 'AWS access key id', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, confidence: 'high' },
  {
    id: 'aws-secret-access-key',
    label: 'AWS secret access key',
    re: /(?:aws_?secret_?access_?key|aws_?secret_?key|secret_?access_?key)["'\]]?\s*(?::|=|=>)\s*["'`]?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/gi,
    group: 1,
    confidence: 'high',
  },
  { id: 'google-api-key', label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, confidence: 'high' },
  { id: 'google-oauth-client-secret', label: 'Google OAuth client secret', re: /\bGOCSPX-[A-Za-z0-9_-]{24,40}\b/g, confidence: 'high' },
  {
    id: 'gcp-service-account-key-id',
    label: 'GCP service-account private_key_id',
    re: /["']private_key_id["']\s*:\s*["']([a-f0-9]{40})["']/g,
    group: 1,
    confidence: 'high',
  },
  {
    id: 'azure-storage-key',
    label: 'Azure storage account key',
    re: /\bAccountKey=([A-Za-z0-9+/]{40,100}={0,2})/g,
    group: 1,
    confidence: 'high',
  },
  {
    id: 'azure-shared-access-key',
    label: 'Azure shared access key',
    re: /\bSharedAccessKey=([A-Za-z0-9+/]{20,100}={0,2})/g,
    group: 1,
    confidence: 'high',
  },
  {
    id: 'azure-sas-signature',
    label: 'Azure SAS signature',
    re: /[?&]sig=([A-Za-z0-9%+/]{30,200}(?:%3D|=){0,2})/g,
    group: 1,
    confidence: 'high',
  },
  // ---- Payments / messaging ----
  { id: 'stripe-secret-key', label: 'Stripe secret / restricted key', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,247}\b/g, confidence: 'high' },
  { id: 'stripe-webhook-secret', label: 'Stripe webhook signing secret', re: /\bwhsec_[A-Za-z0-9]{24,100}\b/g, confidence: 'high' },
  { id: 'stripe-publishable-key', label: 'Stripe publishable key', re: /\bpk_(?:live|test)_[A-Za-z0-9]{16,247}\b/g, confidence: 'low', secret: false },
  { id: 'slack-token', label: 'Slack token', re: /\bxox[abposre]-[A-Za-z0-9-]{10,250}\b/g, confidence: 'high' },
  { id: 'slack-app-token', label: 'Slack app token', re: /\bxapp-\d-[A-Z0-9]{8,20}-\d{6,20}-[a-z0-9]{20,100}\b/gi, confidence: 'high' },
  {
    id: 'slack-webhook',
    label: 'Slack webhook URL',
    re: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/([A-Za-z0-9_/]{20,200})/g,
    group: 1,
    confidence: 'high',
  },
  { id: 'sendgrid-api-key', label: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, confidence: 'high' },
  { id: 'npm-token', label: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g, confidence: 'high' },
  // ---- Supabase ----
  { id: 'supabase-secret-key', label: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{10,200}/g, confidence: 'high' },
  { id: 'supabase-publishable-key', label: 'Supabase publishable key', re: /\bsb_publishable_[A-Za-z0-9_-]{10,200}/g, confidence: 'low', secret: false },
  // ---- Tokens ----
  {
    id: 'jwt',
    label: 'JSON Web Token',
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    confidence: 'high',
    validate: (m) => {
      const payload = jwtPayload(m[0]);
      const role = payload?.role;
      if (role === 'service_role') return { confidence: 'high', secret: true, id: 'supabase-service-role-jwt' };
      // Supabase anon / authenticated keys are public by design (they ship in the frontend).
      if (role === 'anon') return { confidence: 'low', secret: false, id: 'supabase-anon-jwt' };
      return { confidence: 'high', secret: true };
    },
  },
  {
    id: 'private-key',
    label: 'Private key block',
    re: /-----BEGIN (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY(?: BLOCK)?-----/g,
    confidence: 'high',
  },
  { id: 'putty-private-key', label: 'PuTTY private key', re: /PuTTY-User-Key-File-\d: /g, confidence: 'high' },
  {
    id: 'bearer-token',
    label: 'Bearer token',
    re: /\bBearer\s+([A-Za-z0-9._~+/-]{16,4000}=*)/gi,
    group: 1,
    confidence: 'high',
  },
  {
    id: 'basic-auth-header',
    label: 'HTTP Basic credentials',
    re: /\bBasic\s+([A-Za-z0-9+/]{12,1000}={0,2})(?![A-Za-z0-9+/=])/g,
    group: 1,
    confidence: 'low',
    validate: (m) => {
      try {
        const dec = Buffer.from(m[1] ?? '', 'base64').toString('utf8');
        return /^[\x20-\x7e]{1,200}:[\x20-\x7e]{1,200}$/.test(dec) ? { confidence: 'high', secret: true } : null;
      } catch {
        return null;
      }
    },
  },
];
