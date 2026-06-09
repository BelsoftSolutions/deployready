import { runActiveScan, type HttpFn } from '../src/active/runner';
import { decodeJwt } from '../src/active/jwt';
import type { HttpRequestSpec } from '../src/active/types';

function makeJwt(payload: object, sig = 'sigABC'): string {
  const seg = (o: object) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
  return `${seg({ alg: 'HS256', typ: 'JWT' })}.${seg(payload)}.${sig}`;
}

const tokenA = makeJwt({ sub: '1', org_id: 'A' });
const tokenB = makeJwt({ sub: '2', org_id: 'B' });
const profile: HttpRequestSpec = { method: 'GET', path: '/api/profile', query: { org_id: 'A' } };

/** App that verifies signatures (rejects alg:none) and scopes by tenant. */
const secureApp: HttpFn = async (req) => {
  const token = (req.headers.Authorization ?? '').replace('Bearer ', '');
  const d = decodeJwt(token);
  if (!d || d.header.alg === 'none') return { status: 401, bodyText: 'unauthorized' };
  const org = req.query?.org_id;
  if (org && org !== d.payload.org_id) return { status: 403, bodyText: 'forbidden' };
  return { status: 200, bodyText: JSON.stringify({ org_id: d.payload.org_id }) };
};

/** App that does NOT verify signatures and does NOT scope by tenant. */
const vulnApp: HttpFn = async (req) => {
  const org = req.query?.org_id ?? 'A';
  return { status: 200, bodyText: JSON.stringify({ org_id: org, data: 'secret' }) };
};

describe('active/runner', () => {
  it('reports nothing against a secure app', async () => {
    const findings = await runActiveScan({ token: tokenA, tokenB, requests: [profile] }, secureApp);
    expect(findings).toHaveLength(0);
  });

  it('detects a JWT signature that is not verified (alg:none accepted)', async () => {
    const findings = await runActiveScan({ token: tokenA, requests: [profile] }, vulnApp);
    expect(findings.some((f) => f.rule === 'jwt-not-verified')).toBe(true);
  });

  it('detects broken tenant isolation when another tenant’s data is returned', async () => {
    const findings = await runActiveScan({ token: tokenA, tokenB, requests: [profile] }, vulnApp);
    const t = findings.find((f) => f.rule === 'tenant-isolation-broken');
    expect(t).toBeDefined();
    expect(t!.severity).toBe('critical');
    expect(t!.endpoint).toBe('/api/profile');
  });

  it('respects the request budget', async () => {
    let calls = 0;
    const counting: HttpFn = async () => {
      calls++;
      return { status: 200, bodyText: '{}' };
    };
    await runActiveScan({ token: tokenA, tokenB, requests: [profile, profile, profile], maxRequests: 2 }, counting);
    expect(calls).toBeLessThanOrEqual(2);
  });

  it('skips endpoints the test user cannot access (non-2xx baseline)', async () => {
    const denyAll: HttpFn = async () => ({ status: 401, bodyText: 'no' });
    const findings = await runActiveScan({ token: tokenA, tokenB, requests: [profile] }, denyAll);
    expect(findings).toHaveLength(0);
  });

  const admin = { method: 'GET', path: '/admin' } as const;

  it('detects privilege escalation when a forged admin role turns a 403 into a 200', async () => {
    // Trusts the role claim without verifying the signature.
    const vulnAdmin: HttpFn = async (req) => {
      const token = (req.headers.Authorization ?? '').replace('Bearer ', '');
      const role = decodeJwt(token)?.payload.role;
      if (req.path === '/admin') {
        return role === 'admin' ? { status: 200, bodyText: '{"admin":true}' } : { status: 403, bodyText: 'forbidden' };
      }
      return { status: 200, bodyText: '{}' };
    };
    const findings = await runActiveScan({ token: tokenA, requests: [admin] }, vulnAdmin);
    expect(findings.some((f) => f.rule === 'privilege-escalation')).toBe(true);
  });

  it('does not flag privilege escalation when the server verifies the token', async () => {
    const issued = new Set([tokenA, tokenB]);
    const secureAdmin: HttpFn = async (req) => {
      const token = (req.headers.Authorization ?? '').replace('Bearer ', '');
      if (!issued.has(token)) return { status: 401, bodyText: 'bad token' }; // signature verified
      const role = decodeJwt(token)!.payload.role;
      if (req.path === '/admin') {
        return role === 'admin' ? { status: 200, bodyText: 'ok' } : { status: 403, bodyText: 'forbidden' };
      }
      return { status: 200, bodyText: '{}' };
    };
    const findings = await runActiveScan({ token: tokenA, requests: [admin] }, secureAdmin);
    expect(findings).toHaveLength(0);
  });
});
