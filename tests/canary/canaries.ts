/**
 * Synthetic canary credentials, one per detector type. Every value is format-valid but
 * clearly fake, and is assembled at RUNTIME from fragments (with a deterministic
 * pseudo-random body) so this repository never contains a literal that trips GitHub push
 * protection or other secret scanners.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const UPPER_DIGIT = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B64 = ALNUM + '+/';
const HEX = '0123456789abcdef';

let seed = 0x5eed1234;
function rnd(n: number, alphabet = ALNUM): string {
  let s = '';
  for (let i = 0; i < n; i++) {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    s += alphabet[(seed >>> 8) % alphabet.length];
  }
  return s;
}
/** Guarantees mixed case + digit so shape validators accept it. */
function mixed(n: number): string {
  return `Cy7${rnd(n - 3)}`;
}
const j = (...parts: string[]): string => parts.join('');
const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
function jwt(payload: Record<string, unknown>): string {
  return [b64url({ alg: 'HS256', typ: 'JWT' }), b64url(payload), rnd(43, ALNUM + '-_')].join('.');
}
function pemBody(lines: number): string[] {
  return Array.from({ length: lines }, () => `MIIC${rnd(60, B64)}`);
}

export interface Canary {
  /** Detector type this canary exercises. */
  type: string;
  /** The full credential as written into the project. */
  value: string;
  /** Substrings that must never appear in any output (the sensitive part). */
  needles: string[];
}

export function buildCanaries(): Canary[] {
  const c: Canary[] = [];
  const add = (type: string, value: string, ...needles: string[]): void => {
    c.push({ type, value, needles: needles.length ? needles : [value] });
  };
  const body = (v: string, prefixLen: number): string => v.slice(prefixLen);

  const ant = j('sk-', 'ant-', 'api03-', mixed(48));
  add('anthropic', ant, body(ant, 14));
  const oai = j('sk-', 'proj-', mixed(48));
  add('openai', oai, body(oai, 8));
  for (const p of ['ghp', 'gho', 'ghu', 'ghs', 'ghr']) {
    const t = j(p, '_', 'CANARY', rnd(30));
    add(`github-${p}`, t, body(t, 4));
  }
  const pat = j('github', '_pat_', '11CANARY0', rnd(13), '_', rnd(59));
  add('github-fine-grained-pat', pat, body(pat, 11));
  const akia = j('AK', 'IA', 'CANARY', rnd(10, UPPER_DIGIT));
  add('aws-access-key-id', akia, body(akia, 4));
  const awsSecret = j('Cy7', rnd(37, B64));
  add('aws-secret-access-key', awsSecret);
  const gkey = j('AI', 'za', 'SyCANARY', rnd(27, ALNUM + '-_'));
  add('google-api-key', gkey, body(gkey, 4));
  const gcpKeyId = rnd(40, HEX);
  add('gcp-private-key-id', gcpKeyId);
  const gcpPem = pemBody(3);
  add('gcp-service-account-private-key', gcpPem.join('\\n'), ...gcpPem);
  const azure = j(rnd(86, B64), '==');
  add('azure-storage-key', azure, azure.slice(0, 40));
  const sas = j('Cy7', rnd(40, ALNUM), '%3D');
  add('azure-sas-sig', sas, sas.slice(0, 30));
  const sk = j('sk', '_live_', 'CANARY', rnd(24));
  add('stripe-secret', sk, body(sk, 8));
  const rk = j('rk', '_test_', 'CANARY', rnd(24));
  add('stripe-restricted', rk, body(rk, 8));
  const whsec = j('wh', 'sec_', 'CANARY', rnd(26));
  add('stripe-webhook', whsec, body(whsec, 6));
  const slack = j('xo', 'xb-', '1234567890', '-', '9876543210', '-', 'CANARY', rnd(18));
  add('slack-token', slack, body(slack, 5));
  const hook = j('https://hooks.', 'slack.com/services/', 'T0CANARY1', '/', 'B0CANARY2', '/', rnd(24));
  add('slack-webhook', hook, hook.slice(-24));
  const sbSecret = j('sb_', 'secret_', 'CANARY', rnd(26));
  add('supabase-secret-key', sbSecret, body(sbSecret, 10));
  const service = jwt({ iss: 'supabase', ref: 'canaryrefcanaryref00', role: 'service_role', iat: 1700000000, exp: 2000000000 });
  add('supabase-service-role-jwt', service, service.split('.')[1]!, service.split('.')[2]!);
  const genericJwt = jwt({ sub: 'canary-user', name: 'Canary', iat: 1700000000 });
  add('jwt', genericJwt, genericJwt.split('.')[2]!);
  const rsa = pemBody(4);
  add('rsa-private-key-multiline', rsa.join('\n'), ...rsa);
  const ssh = pemBody(3);
  add('openssh-private-key-multiline', ssh.join('\n'), ...ssh);
  const pgPw = j('Pg', mixed(14), '!x');
  add('postgres-url', pgPw);
  const amqpPw = j('Mq', mixed(14));
  add('amqp-url', amqpPw);
  const redisPw = j('Rd', mixed(14));
  add('redis-url', redisPw);
  const qTok = mixed(32);
  add('url-query-token', qTok);
  const qKey = mixed(32);
  add('url-query-key', qKey);
  const qPw = j('Qp', mixed(12));
  add('url-query-password', qPw);
  const bearer = mixed(40);
  add('http-authorization-bearer', bearer);
  const basic = Buffer.from(j('admin:', 'Bc', mixed(14))).toString('base64');
  add('http-authorization-basic', basic);
  const cookie = mixed(32);
  add('http-cookie', cookie);
  const setCookie = mixed(32);
  add('http-set-cookie', setCookie);
  const jsonPw = j('hunter2', mixed(10));
  add('json-password', jsonPw);
  const yamlPw = j('Ym', mixed(14));
  add('yaml-password', yamlPw);
  const tomlTok = j('Tm', mixed(20));
  add('toml-token', tomlTok);
  const envSecret = j('Ev', mixed(24));
  add('env-secret', envSecret);
  const entropyTok = rnd(40, ALNUM + '_-');
  add('generic-high-entropy', entropyTok);
  const prefixed = j('test-', 'Xy9!', mixed(10));
  add('placeholder-prefixed-password', prefixed, prefixed);
  const demo = j('demo', mixed(10));
  add('placeholder-prefixed-demo', demo, demo);
  return c;
}

/** Public values that must NOT be reported as secrets (they ship to browsers by design). */
export function publicValues(): { publishable: string; anonJwt: string; stripePk: string } {
  return {
    publishable: j('sb_', 'publishable_', 'CANARY', rnd(26)),
    anonJwt: jwt({ iss: 'supabase', ref: 'canaryrefcanaryref00', role: 'anon', iat: 1700000000, exp: 2000000000 }),
    stripePk: j('pk', '_live_', 'CANARY', rnd(24)),
  };
}

/** Write a synthetic project containing every canary in its natural file format. */
export function writeCanaryProject(canaries: Canary[]): string {
  const v = (type: string): string => {
    const found = canaries.find((x) => x.type === type);
    if (!found) throw new Error(`no canary ${type}`);
    return found.value;
  };
  const pub = publicValues();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-canary-'));
  const w = (rel: string, text: string): void => {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  };
  w('package.json', JSON.stringify({ name: 'canary-app', dependencies: { express: '4.18.0', '@supabase/supabase-js': '2.0.0' } }, null, 2));
  w(
    'src/config.ts',
    [
      `export const anthropicKey = "${v('anthropic')}";`,
      `export const openaiKey = "${v('openai')}";`,
      ...['ghp', 'gho', 'ghu', 'ghs', 'ghr'].map((p) => `export const gh_${p} = "${v(`github-${p}`)}";`),
      `export const githubPat = "${v('github-fine-grained-pat')}";`,
      `export const awsKeyId = "${v('aws-access-key-id')}";`,
      `export const aws_secret_access_key = "${v('aws-secret-access-key')}";`,
      `export const mapsKey = "${v('google-api-key')}";`,
      `export const storage = "DefaultEndpointsProtocol=https;AccountName=canary;AccountKey=${v('azure-storage-key')};EndpointSuffix=core.windows.net";`,
      `export const blobUrl = "https://canary.blob.core.windows.net/c/f.txt?sv=2022-11-02&se=2030-01-01&sp=r&sig=${v('azure-sas-sig')}";`,
      `export const stripeKey = "${v('stripe-secret')}";`,
      `export const stripeRestricted = "${v('stripe-restricted')}";`,
      `export const stripeWebhook = "${v('stripe-webhook')}";`,
      `export const slackBot = "${v('slack-token')}";`,
      `export const slackHook = "${v('slack-webhook')}";`,
      `export const supabaseSecret = "${v('supabase-secret-key')}";`,
      `export const serviceRole = "${v('supabase-service-role-jwt')}";`,
      `export const sessionJwt = "${v('jwt')}";`,
      `export const db = "postgres://app:${v('postgres-url')}@db.internal:5432/app";`,
      `export const queue = "amqp://worker:${v('amqp-url')}@mq.internal:5672/";`,
      `export const cache = "redis://:${v('redis-url')}@cache.internal:6379/0";`,
      `export const api = "https://api.canary.test/v1/items?token=${v('url-query-token')}&key=${v('url-query-key')}&password=${v('url-query-password')}";`,
      `export const clientSecret = "${v('generic-high-entropy')}";`,
      `export const password = "${v('placeholder-prefixed-password')}";`,
      `export const adminPassword = "${v('placeholder-prefixed-demo')}";`,
      // Public values: never reported as secrets.
      `export const publishable = "${pub.publishable}";`,
      `export const anonKey = "${pub.anonJwt}";`,
      `export const stripePk = "${pub.stripePk}";`,
      '',
    ].join('\n'),
  );
  w(
    'service-account.json',
    JSON.stringify(
      {
        type: 'service_account',
        project_id: 'canary-project',
        private_key_id: v('gcp-private-key-id'),
        private_key: `-----BEGIN PRIVATE KEY-----\n${v('gcp-service-account-private-key').split('\\n').join('\n')}\n-----END PRIVATE KEY-----\n`,
        client_email: 'canary@canary-project.iam.gserviceaccount.com',
      },
      null,
      2,
    ),
  );
  w('keys/server.pem', `-----BEGIN RSA PRIVATE KEY-----\n${v('rsa-private-key-multiline')}\n-----END RSA PRIVATE KEY-----\n`);
  w('keys/deploy_key', `-----BEGIN OPENSSH PRIVATE KEY-----\n${v('openssh-private-key-multiline')}\n-----END OPENSSH PRIVATE KEY-----\n`);
  w(
    'docs/request.http',
    [
      'GET /v1/me HTTP/1.1',
      'Host: api.canary.test',
      `Authorization: Bearer ${v('http-authorization-bearer')}`,
      `Cookie: session=${v('http-cookie')}; theme=dark`,
      '',
      'HTTP/1.1 200 OK',
      `Set-Cookie: sid=${v('http-set-cookie')}; Path=/; HttpOnly`,
      '',
      'GET /admin HTTP/1.1',
      `Authorization: Basic ${v('http-authorization-basic')}`,
      '',
    ].join('\n'),
  );
  w('config/settings.json', `{"db":{"host":"db.internal","password":"${v('json-password')}"}}\n`);
  w('config/app.yml', `database:\n  host: db.internal\n  db_password: ${v('yaml-password')}\n`);
  w('config/app.toml', `[api]\napi_token = "${v('toml-token')}"\n`);
  w('.env', `SECRET_KEY=${v('env-secret')}\nPORT=3000\n`);
  w(
    'server.js',
    [
      "const express = require('express');",
      "const crypto = require('crypto');",
      'const app = express();',
      "app.delete('/api/users/:id', (req, res) => res.json({ ok: true }));",
      "const h = crypto.createHash('md5');",
      'module.exports = { app, h };',
      '',
    ].join('\n'),
  );
  return root;
}

/** Every needle that leaked into `text`, labelled by canary type. */
export function leaks(text: string, canaries: Canary[]): string[] {
  const out: string[] = [];
  for (const c of canaries) for (const n of c.needles) if (n && text.includes(n)) out.push(c.type);
  return [...new Set(out)];
}
