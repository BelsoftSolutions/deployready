import { decodeJwt, forgeNoneAlg, tamperClaimsKeepSig } from '../src/active/jwt';

/** Build a real-looking JWT (header.payload.signature) for tests. */
function makeJwt(header: object, payload: object, sig = 'sigabc'): string {
  const seg = (o: object) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
  return `${seg(header)}.${seg(payload)}.${sig}`;
}

describe('active/jwt', () => {
  const token = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', role: 'user', org_id: 'A' });

  it('decodes header and payload', () => {
    const d = decodeJwt(token);
    expect(d).not.toBeNull();
    expect(d!.header.alg).toBe('HS256');
    expect(d!.payload.role).toBe('user');
    expect(d!.signature).toBe('sigabc');
  });

  it('returns null for a non-JWT string', () => {
    expect(decodeJwt('not.a.jwt.token')).toBeNull();
    expect(decodeJwt('garbage')).toBeNull();
    expect(decodeJwt('a.b.c')).toBeNull(); // not valid base64url JSON
  });

  it('forges an alg:none token with patched claims and an empty signature', () => {
    const forged = forgeNoneAlg(token, { role: 'admin' });
    expect(forged).not.toBeNull();
    expect(forged!.endsWith('.')).toBe(true); // empty signature segment
    const d = decodeJwt(forged!);
    expect(d!.header.alg).toBe('none');
    expect(d!.payload.role).toBe('admin'); // escalated
    expect(d!.payload.sub).toBe('1'); // other claims preserved
  });

  it('tampers claims while keeping the original signature (tests apps that skip verification)', () => {
    const tampered = tamperClaimsKeepSig(token, { org_id: 'B' });
    expect(tampered).not.toBeNull();
    const d = decodeJwt(tampered!);
    expect(d!.signature).toBe('sigabc'); // signature unchanged
    expect(d!.payload.org_id).toBe('B'); // tenant swapped
    expect(d!.header.alg).toBe('HS256'); // header unchanged
  });

  it('returns null when asked to tamper a non-JWT', () => {
    expect(forgeNoneAlg('nope')).toBeNull();
    expect(tamperClaimsKeepSig('nope', { x: 1 })).toBeNull();
  });
});
