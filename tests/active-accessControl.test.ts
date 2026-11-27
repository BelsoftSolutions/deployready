import { assessAuthz, bodiesEqual, isSensitiveKey, maskBody, maskValue, semanticEqual, type AuthzInput } from '../src/active/accessControl';

const r = (status: number, body: unknown) => ({ status, bodyText: typeof body === 'string' ? body : JSON.stringify(body) });

const alice = { id: 'inv_1', owner: 'alice', email: 'alice@example.test', amount: 1250.5, status: 'paid', items: [{ sku: 'A-1' }, { sku: 'A-2' }] };
const bob = { id: 'inv_2', owner: 'bob', email: 'bob@example.test', amount: 8730.25, status: 'paid', items: [{ sku: 'B-7' }, { sku: 'B-9' }] };

const base = (over: Partial<AuthzInput> = {}): AuthzInput => ({
  tampered: r(200, bob),
  ownBaselines: [r(200, alice), r(200, alice)],
  ownerBaselines: [r(200, bob), r(200, bob)],
  foreignValue: 'bob',
  ownValue: 'alice',
  ...over,
});

describe('active/accessControl — semantic verdicts', () => {
  it('confirms a full leak of the owner record', () => {
    const v = assessAuthz(base());
    expect(v.verdict).toBe('confirmed-vulnerable');
    expect(v.disclosed.map((d) => d.path)).toEqual(expect.arrayContaining(['email', 'amount', 'id']));
    expect(v.disclosed.find((d) => d.path === 'email')).toMatchObject({ sensitive: true, masked: 'b***@e***.test' });
    expect(JSON.stringify(v.disclosed)).not.toContain('bob@example.test');
    expect(v.reason).toMatch(/same record the owner receives/);
  });

  it('ignores volatile metadata learned from two owner baselines', () => {
    const withMeta = (meta: object, inv: object) => ({ meta, invoice: inv });
    const v = assessAuthz(
      base({
        tampered: r(200, withMeta({ rid: 'r3', gen: 3 }, bob)),
        ownBaselines: [r(200, withMeta({ rid: 'r1', gen: 1 }, alice)), r(200, withMeta({ rid: 'r2', gen: 2 }, alice))],
        ownerBaselines: [r(200, withMeta({ rid: 'r4', gen: 4 }, bob)), r(200, withMeta({ rid: 'r5', gen: 5 }, bob))],
      }),
    );
    expect(v.verdict).toBe('confirmed-vulnerable');
    expect(v.ignored).toEqual(expect.arrayContaining(['meta.rid', 'meta.gen']));
    expect(v.reason).toMatch(/same record/);
  });

  it('ignores well-known volatile names and configured fields even with one baseline each', () => {
    expect(semanticEqual('{"a":1,"requestId":"x","nonce":"n1"}', '{"a":1,"requestId":"y","nonce":"n2"}')).toBe(true);
    expect(semanticEqual('{"a":1,"meta":{"build":"1"}}', '{"a":1,"meta":{"build":"2"}}', ['meta.build'])).toBe(true);
    expect(semanticEqual('{"a":1,"build":"1"}', '{"a":1,"build":"2"}')).toBe(false);
  });

  it('compares nested objects and arrays order-insensitively', () => {
    expect(semanticEqual('{"x":{"list":[1,2,3]},"y":"a"}', '{"y":"a","x":{"list":[3,1,2]}}')).toBe(true);
    expect(semanticEqual('{"x":[1,2]}', '{"x":[1,3]}')).toBe(false);
  });

  it('confirms a partial disclosure of a private field', () => {
    const v = assessAuthz(base({ tampered: r(200, { summary: { contact: 'bob@example.test' }, status: 'paid' }) }));
    expect(v.verdict).toBe('confirmed-vulnerable');
    expect(v.reason).toMatch(/Partial disclosure/);
    expect(v.disclosed).toEqual([{ path: 'email', sensitive: true, masked: 'b***@e***.test' }]);
  });

  it('inspects 401/403/404 bodies: a refusal status carrying owner data is still a leak', () => {
    for (const status of [401, 403, 404]) {
      const v = assessAuthz(base({ tampered: r(status, { error: 'not found', debug: bob }) }));
      expect(v.verdict).toBe('confirmed-vulnerable');
      expect(v.reason).toMatch(/status codes are not proof/);
    }
  });

  it('verifies a clean refusal when the owner can read the resource', () => {
    for (const status of [401, 403, 404]) {
      expect(assessAuthz(base({ tampered: r(status, { error: 'forbidden' }) })).verdict).toBe('verified-denied');
    }
  });

  it('a requested-id echo is not disclosure', () => {
    for (const body of [{ error: 'not found', id: 'bob' }, { requested: 'bob' }]) {
      const v = assessAuthz(base({ tampered: r(200, body) }));
      expect(v.verdict).toBe('verified-denied');
      expect(v.reason).toMatch(/echoes the requested id/);
    }
  });

  it('the swapped id being ignored (own data returned) is safe, with an explanation', () => {
    const v = assessAuthz(base({ tampered: r(200, { ...alice, requestId: 'zzz' }) }));
    expect(v.verdict).toBe('verified-denied');
    expect(v.ownData).toBe(true);
    expect(v.reason).toMatch(/ignored the swapped id/);
  });

  it('one non-sensitive matching value is only suspected', () => {
    const v = assessAuthz(base({ tampered: r(200, { ref: 'inv_2' }) }));
    expect(v.verdict).toBe('suspected');
  });

  it('data that is neither yours nor the owner’s is inconclusive', () => {
    expect(assessAuthz(base({ tampered: r(200, { someone: 'carol', note: 'other' }) })).verdict).toBe('inconclusive');
    expect(assessAuthz(base({ tampered: r(500, 'boom') })).verdict).toBe('inconclusive');
  });

  it('without a working owner baseline a refusal proves nothing and an echo is never a finding', () => {
    expect(assessAuthz(base({ ownerBaselines: [r(404, {})], tampered: r(403, {}) })).verdict).toBe('inconclusive');
    expect(assessAuthz(base({ ownerBaselines: [r(404, {})], tampered: r(200, { requested: 'bob' }) })).verdict).toBe('inconclusive');
    const s = assessAuthz(base({ ownerBaselines: [], tampered: r(200, { phone: '+1 555 0100' }) }));
    expect(s.verdict).toBe('suspected');
  });

  it('declared-public routes are intentionally-public', () => {
    expect(assessAuthz(base({ policy: { declaredPublic: true } })).verdict).toBe('intentionally-public');
  });

  it('anonymous control: same non-sensitive data for everyone is intentionally-public', () => {
    const p1 = { id: '1', name: 'widget', category: 'tools' };
    const p2 = { id: '2', name: 'gadget', category: 'toys' };
    const input = base({ tampered: r(200, p2), ownBaselines: [r(200, p1)], ownerBaselines: [r(200, p2), r(200, p2)], foreignValue: '2', ownValue: '1' });
    const first = assessAuthz(input);
    expect(first.wantsAnonymousControl).toBe(true);
    expect(assessAuthz({ ...input, anonymous: r(200, p2) }).verdict).toBe('intentionally-public');
    expect(assessAuthz({ ...input, anonymous: r(401, {}) }).verdict).toBe(first.verdict);
  });

  it('anonymous control: sensitive data readable without credentials stays confirmed', () => {
    const v = assessAuthz({ ...base(), anonymous: r(200, bob) });
    expect(v.verdict).toBe('confirmed-vulnerable');
    expect(v.reason).toMatch(/WITHOUT credentials/);
  });

  it('does not treat link fields templated on the id as owner markers', () => {
    const v = assessAuthz(
      base({
        tampered: r(200, { self: '/api/users/bob/invoice', error: 'gone' }),
        ownBaselines: [r(200, { ...alice, self: '/api/users/alice/invoice' })],
        ownerBaselines: [r(200, { ...bob, self: '/api/users/bob/invoice' })],
      }),
    );
    expect(v.verdict).toBe('verified-denied');
  });

  it('non-JSON bodies fall back to stable text tokens', () => {
    const v = assessAuthz(
      base({
        tampered: r(200, '<p>Invoice for bob@example.test total 8730.25 VIP-customer</p>'),
        ownBaselines: [r(200, '<p>Invoice for alice@example.test total 1250.50</p>')],
        ownerBaselines: [r(200, '<p>Invoice for bob@example.test total 8730.25 VIP-customer</p>'), r(200, '<p>Invoice for bob@example.test total 8730.25 VIP-customer</p>')],
      }),
    );
    expect(v.verdict).toBe('confirmed-vulnerable');
  });
});

describe('active/accessControl — helpers', () => {
  it('classifies sensitive keys by name', () => {
    for (const k of ['email', 'billingAddress', 'phone_number', 'ssn', 'cardLast4', 'apiToken', 'client_secret', 'message', 'notes', 'amount', 'grandTotal', 'firstName']) {
      expect(isSensitiveKey(k)).toBe(true);
    }
    for (const k of ['id', 'name', 'status', 'totalPages', 'createdAt', 'sku', 'itemCount']) expect(isSensitiveKey(k)).toBe(false);
  });

  it('masks values and never returns them raw', () => {
    expect(maskValue('bob@example.test')).toBe('b***@e***.test');
    expect(maskValue('8730.25', 'number')).toBe('8•••.••');
    expect(maskValue('abc')).toBe('****');
    expect(maskValue('VIP customer')).toBe('VI… (12 chars)');
    const masked = maskBody('{"email":"bob@example.test","amount":8730.25}', ['bob@example.test', '8730.25']);
    expect(masked).not.toContain('bob@example.test');
    expect(masked).not.toContain('8730.25');
  });

  it('bodiesEqual keeps strict canonical-JSON equality', () => {
    expect(bodiesEqual('{"a":1,"b":{"c":[1,2]}}', '{ "b": {"c":[1,2]}, "a": 1 }')).toBe(true);
    expect(bodiesEqual('[1,2]', '[2,1]')).toBe(false);
    expect(bodiesEqual('  hello\n', 'hello')).toBe(true);
  });
});
