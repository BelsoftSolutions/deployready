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
  if (!req.headers.Authorization) return { status: 401, bodyText: 'unauthorized' };
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

  describe('jwt-not-verified needs an unauthenticated control', () => {
    type Req = Parameters<HttpFn>[0];
    const noToken = (req: Req) => !req.headers.Authorization;
    const isValid = (req: Req) => req.headers.Authorization === `Bearer ${tokenA}`;
    const ok = { status: 200, bodyText: '{}' };
    const denied = { status: 401, bodyText: 'unauthorized' };
    const other: HttpRequestSpec = { method: 'GET', path: '/api/settings' };

    it('does not report a public route that accepts any request', async () => {
      const publicApp: HttpFn = async () => ok;
      const findings = await runActiveScan({ token: tokenA, requests: [profile] }, publicApp);
      expect(findings.some((f) => f.rule === 'jwt-not-verified')).toBe(false);
    });

    it('reports a protected route that accepts alg:none', async () => {
      const app: HttpFn = async (req) => (noToken(req) ? denied : ok);
      const findings = await runActiveScan({ token: tokenA, requests: [profile] }, app);
      const f = findings.find((x) => x.rule === 'jwt-not-verified');
      expect(f?.severity).toBe('critical');
      expect(f?.endpoint).toBe('/api/profile');
    });

    it('also treats a 403 control as protected', async () => {
      const app: HttpFn = async (req) => (noToken(req) ? { status: 403, bodyText: 'no' } : ok);
      const findings = await runActiveScan({ token: tokenA, requests: [profile] }, app);
      expect(findings.some((f) => f.rule === 'jwt-not-verified')).toBe(true);
    });

    it('does not report a protected route that rejects alg:none', async () => {
      const app: HttpFn = async (req) => (isValid(req) ? ok : denied);
      const findings = await runActiveScan({ token: tokenA, requests: [profile] }, app);
      expect(findings.some((f) => f.rule === 'jwt-not-verified')).toBe(false);
    });

    it('skips a public first endpoint and reports on the protected, vulnerable second one', async () => {
      const app: HttpFn = async (req) => {
        if (req.path === '/api/profile') return ok;
        return noToken(req) ? denied : ok;
      };
      const findings = await runActiveScan({ token: tokenA, requests: [profile, other] }, app);
      const jwt = findings.filter((f) => f.rule === 'jwt-not-verified');
      expect(jwt).toHaveLength(1);
      expect(jwt[0].endpoint).toBe('/api/settings');
    });

    it('reports nothing when no endpoint gives a 401/403 control (does not guess)', async () => {
      const app: HttpFn = async (req) => (noToken(req) ? { status: 404, bodyText: 'x' } : ok);
      const findings = await runActiveScan({ token: tokenA, requests: [profile, other] }, app);
      expect(findings.some((f) => f.rule === 'jwt-not-verified')).toBe(false);
    });

    it('reports jwt-not-verified only once across endpoints', async () => {
      const app: HttpFn = async (req) => (noToken(req) ? denied : ok);
      const findings = await runActiveScan({ token: tokenA, requests: [profile, other] }, app);
      expect(findings.filter((f) => f.rule === 'jwt-not-verified')).toHaveLength(1);
    });

    it('counts the control request against the budget', async () => {
      let calls = 0;
      const app: HttpFn = async (req) => {
        calls++;
        return noToken(req) ? denied : ok;
      };
      const full = await runActiveScan({ token: tokenA, requests: [profile], maxRequests: 3 }, app);
      expect(calls).toBe(3);
      expect(full.some((f) => f.rule === 'jwt-not-verified')).toBe(true);

      calls = 0;
      const tight = await runActiveScan({ token: tokenA, requests: [profile], maxRequests: 2 }, app);
      expect(calls).toBeLessThanOrEqual(2);
      expect(tight.some((f) => f.rule === 'jwt-not-verified')).toBe(false);
    });
  });
});

describe('active/runner — param-aware cross-access', () => {
  const tokenU1 = makeJwt({ sub: 'u1', org_id: 'orgA' });
  const tokenU2 = makeJwt({ sub: 'u2', org_id: 'orgB' });
  const userReq: HttpRequestSpec = { method: 'GET', path: '/users/u1', pathParams: [{ index: 2, name: 'id' }] };
  const orgReq: HttpRequestSpec = { method: 'GET', path: '/orgs/orgA/projects', pathParams: [{ index: 2, name: 'orgId' }] };

  it('finds an IDOR on a string id param (/users/:id with u1/u2)', async () => {
    const app: HttpFn = async (req) => {
      const id = req.path.split('/')[2];
      return { status: 200, bodyText: JSON.stringify({ id, email: `${id}@example.test` }) };
    };
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq] }, app);
    const f = findings.find((x) => x.rule === 'bola-idor');
    expect(f).toBeDefined();
    expect(f!.endpoint).toBe('/users/u1');
  });

  it('does not flag a string-id endpoint that denies foreign ids', async () => {
    const app: HttpFn = async (req) =>
      req.path === '/users/u1' ? { status: 200, bodyText: '{"id":"u1"}' } : { status: 403, bodyText: 'forbidden' };
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq] }, app);
    expect(findings.filter((f) => f.rule === 'bola-idor')).toHaveLength(0);
  });

  it('reports a tenant path param as tenant-isolation-broken, not bola-idor', async () => {
    const app: HttpFn = async (req) => {
      const org = req.path.split('/')[2];
      return { status: 200, bodyText: JSON.stringify({ org, projects: [`${org}-p1`] }) };
    };
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [orgReq] }, app);
    expect(findings.some((f) => f.rule === 'tenant-isolation-broken' && f.endpoint === '/orgs/orgA/projects')).toBe(true);
    expect(findings.some((f) => f.rule === 'bola-idor')).toBe(false);
  });

  it('does not flag an isolated tenant path param', async () => {
    const app: HttpFn = async (req) =>
      req.path.split('/')[2] === 'orgA' ? { status: 200, bodyText: '{"org":"orgA"}' } : { status: 404, bodyText: 'nope' };
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [orgReq] }, app);
    expect(findings).toHaveLength(0);
  });
});

describe('active/runner — owner-baseline proof', () => {
  const tokenU1 = makeJwt({ sub: 'u1', org_id: 'orgA' });
  const tokenU2 = makeJwt({ sub: 'u2', org_id: 'orgB' });
  const num1 = makeJwt({ sub: '1' });
  const num2 = makeJwt({ sub: '2' });
  const userReq: HttpRequestSpec = { method: 'GET', path: '/users/u1', pathParams: [{ index: 2, name: 'id' }] };
  const subOf = (req: Parameters<HttpFn>[0]) => decodeJwt((req.headers.Authorization ?? '').replace('Bearer ', ''))?.payload.sub;
  const DATA: Record<string, object> = { u1: { name: 'Alice', plan: 'free' }, u2: { name: 'Bob', plan: 'pro' } };
  const idOf = (req: Parameters<HttpFn>[0]) => req.path.split('/')[2]!;

  it('still finds a numeric-id IDOR whose body echoes the id', async () => {
    const app: HttpFn = async (req) => ({ status: 200, bodyText: JSON.stringify({ id: idOf(req), secret: 's' + idOf(req) }) });
    const reqs = [{ method: 'GET', path: '/users/1', pathParams: [{ index: 2, name: 'id' }] }];
    const findings = await runActiveScan({ token: num1, tokenB: num2, requests: reqs }, app);
    expect(findings.some((f) => f.rule === 'bola-idor')).toBe(true);
  });

  it('finds an IDOR whose response does not echo the id but equals the owner baseline', async () => {
    const app: HttpFn = async (req) => ({ status: 200, bodyText: JSON.stringify(DATA[idOf(req)] ?? {}) });
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq] }, app);
    const f = findings.find((x) => x.rule === 'bola-idor');
    expect(f).toBeDefined();
    expect(f!.description).toMatch(/exactly what that identity itself receives/);
  });

  it('compares bodies as canonical JSON (key order and whitespace do not matter)', async () => {
    const app: HttpFn = async (req) =>
      subOf(req) === 'u2' || idOf(req) === 'u2'
        ? { status: 200, bodyText: '{"name":"Bob","plan":"pro"}' }
        : { status: 200, bodyText: '{ "plan": "free", "name": "Alice" }' };
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq] }, app);
    expect(findings.some((f) => f.rule === 'bola-idor')).toBe(true);
  });

  it('does not report a 200 error body that merely mentions the id and is not the owner baseline', async () => {
    const app: HttpFn = async (req) =>
      idOf(req) === subOf(req)
        ? { status: 200, bodyText: JSON.stringify(DATA[idOf(req)]) }
        : { status: 200, bodyText: JSON.stringify({ error: `user ${idOf(req)} not found` }) };
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq] }, app);
    expect(findings).toHaveLength(0);
  });

  it('does not report an endpoint that ignores the id and returns the caller’s own data', async () => {
    const app: HttpFn = async (req) => ({ status: 200, bodyText: JSON.stringify({ me: subOf(req), ...DATA[String(subOf(req))] }) });
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq] }, app);
    expect(findings).toHaveLength(0);
  });

  it('does not report a properly isolated app (403 / 404)', async () => {
    for (const status of [403, 404]) {
      const app: HttpFn = async (req) =>
        idOf(req) === subOf(req) ? { status: 200, bodyText: JSON.stringify(DATA[idOf(req)]) } : { status, bodyText: 'no' };
      const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq] }, app);
      expect(findings.filter((f) => f.rule === 'bola-idor')).toHaveLength(0);
    }
  });

  it('falls back to the echo proof when the owner baseline is unavailable', async () => {
    const app: HttpFn = async (req) =>
      subOf(req) === 'u2'
        ? { status: 500, bodyText: 'owner path broken' }
        : { status: 200, bodyText: JSON.stringify({ id: idOf(req), data: 'x' }) };
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq] }, app);
    const f = findings.find((x) => x.rule === 'bola-idor');
    expect(f).toBeDefined();
    expect(f!.description).toMatch(/no owner baseline/);
  });

  it('does not report echo-only when the owner baseline exists and disagrees', async () => {
    const app: HttpFn = async (req) =>
      subOf(req) === 'u2'
        ? { status: 200, bodyText: '{"name":"Bob"}' }
        : { status: 200, bodyText: JSON.stringify({ id: idOf(req), note: 'generic' }) };
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq] }, app);
    expect(findings).toHaveLength(0);
  });

  it('does not treat a matching empty body as proof', async () => {
    const app: HttpFn = async (req) =>
      idOf(req) === 'u1' ? { status: 200, bodyText: '{"name":"Alice"}' } : { status: 200, bodyText: '{}' };
    const findings = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq] }, app);
    expect(findings).toHaveLength(0);
  });

  it('counts owner-baseline requests against the budget', async () => {
    let calls = 0;
    const app: HttpFn = async (req) => {
      calls++;
      return { status: 200, bodyText: JSON.stringify(DATA[idOf(req)] ?? {}) };
    };
    // baseline, anonymous control, tampered, owner baseline
    const tight = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq], maxRequests: 3 }, app);
    expect(calls).toBeLessThanOrEqual(3);
    expect(tight.some((f) => f.rule === 'bola-idor')).toBe(false);

    calls = 0;
    const full = await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq], maxRequests: 4 }, app);
    expect(calls).toBe(4);
    expect(full.some((f) => f.rule === 'bola-idor')).toBe(true);
  });

  it('fetches each owner baseline only once per path', async () => {
    let ownerCalls = 0;
    const app: HttpFn = async (req) => {
      if (subOf(req) === 'u2') ownerCalls++;
      return { status: 200, bodyText: JSON.stringify(DATA[idOf(req)] ?? {}) };
    };
    await runActiveScan({ token: tokenU1, tokenB: tokenU2, requests: [userReq, userReq] }, app);
    expect(ownerCalls).toBe(1);
  });
});
