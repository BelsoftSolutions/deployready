import { LINE_FIXERS, fixLine } from '../src/agent/lineFixers';

describe('deterministic line fixers', () => {
  it('weak-hash: rewrites JS md5/sha1 to sha256, preserving quotes', () => {
    expect(fixLine('weak-hash', "const h = crypto.createHash('md5');")).toBe(
      "const h = crypto.createHash('sha256');",
    );
    expect(fixLine('weak-hash', 'createHash("sha1")')).toBe('createHash("sha256")');
  });

  it('py-weak-hash: rewrites hashlib.md5/sha1 to sha256', () => {
    expect(fixLine('py-weak-hash', 'h = hashlib.md5(data)')).toBe('h = hashlib.sha256(data)');
    expect(fixLine('py-weak-hash', 'hashlib.sha1()')).toBe('hashlib.sha256()');
  });

  it('py-yaml-load: rewrites yaml.load( to yaml.safe_load(', () => {
    expect(fixLine('py-yaml-load', 'cfg = yaml.load(f)')).toBe('cfg = yaml.safe_load(f)');
  });

  it('tls-verification-disabled: flips rejectUnauthorized:false to true', () => {
    expect(fixLine('tls-verification-disabled', '{ rejectUnauthorized: false }')).toBe(
      '{ rejectUnauthorized: true }',
    );
  });

  it('py-requests-noverify: flips verify=False to True', () => {
    expect(fixLine('py-requests-noverify', 'requests.get(url, verify=False)')).toBe(
      'requests.get(url, verify=True)',
    );
  });

  it('py-flask-debug: flips debug=True to False', () => {
    expect(fixLine('py-flask-debug', 'app.run(debug=True)')).toBe('app.run(debug=False)');
  });

  it('returns null when the line does not match (e.g. env-var TLS form)', () => {
    expect(fixLine('tls-verification-disabled', "NODE_TLS_REJECT_UNAUTHORIZED='0'")).toBeNull();
  });

  it('returns null for an unknown rule', () => {
    expect(fixLine('no-such-rule', 'anything')).toBeNull();
  });

  it('exposes the fixable rule keys', () => {
    expect(Object.keys(LINE_FIXERS).sort()).toEqual(
      [
        'py-flask-debug',
        'py-requests-noverify',
        'py-weak-hash',
        'py-yaml-load',
        'tls-verification-disabled',
        'weak-hash',
      ].sort(),
    );
  });
});
