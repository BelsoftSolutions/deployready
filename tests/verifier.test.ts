jest.mock('../src/analysis/VulnerabilityDetector', () => ({ VulnerabilityDetector: { scan: jest.fn() } }));
jest.mock('../src/dynamic/DynamicTester', () => ({ DynamicTester: { run: jest.fn() } }));
jest.mock('../src/dynamic/LocalhostDetector', () => ({ LocalhostDetector: { find: jest.fn() } }));

import { Verifier } from '../src/core/Verifier';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { DynamicTester } from '../src/dynamic/DynamicTester';
import { LocalhostDetector } from '../src/dynamic/LocalhostDetector';
import { makeFinding } from '../src/utils/finding';
import type { Finding, Route } from '../src/types';

const scan = VulnerabilityDetector.scan as jest.Mock;
const run = DynamicTester.run as jest.Mock;
const find = LocalhostDetector.find as jest.Mock;

function mk(over: Partial<Finding>): Finding {
  return makeFinding({
    rule: 'hardcoded-secret', title: 'T', severity: 'critical', category: 'security', source: 'static',
    description: 'd', recommendation: 'r', file: 'src/a.js', line: 3, evidence: 'KEY = «REDACTED»', ...over,
  });
}

const routes: Route[] = [{ method: 'GET', path: '/x', file: 'a.js', guarded: false }];

beforeEach(() => jest.resetAllMocks());

describe('Verifier: AI findings', () => {
  it('are never mechanically verifiable', async () => {
    const r = await Verifier.verify(mk({ source: 'ai' }), { target: '/p' });
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/AI-inferred/);
    expect(scan).not.toHaveBeenCalled();
    expect(run).not.toHaveBeenCalled();
  });
});

describe('Verifier: static findings', () => {
  it('reports fixed when the rule no longer fires in that file', async () => {
    scan.mockResolvedValue([mk({ file: 'src/other.js' }), mk({ rule: 'other-rule' })]);
    expect(await Verifier.verify(mk({}), { target: '/p' })).toEqual({ status: 'fixed' });
    expect(scan).toHaveBeenCalledWith('/p');
  });

  it('reports still-present when rule, file and evidence all match', async () => {
    scan.mockResolvedValue([mk({})]);
    const r = await Verifier.verify(mk({}), { target: '/p' });
    expect(r.status).toBe('still-present');
    expect(r.detail).toMatch(/still appears/);
  });

  it('matches on evidence, so fixing one of several same-rule issues in a file counts as fixed', async () => {
    scan.mockResolvedValue([mk({ evidence: 'OTHER = «REDACTED»', line: 9 })]);
    expect((await Verifier.verify(mk({}), { target: '/p' })).status).toBe('fixed');
  });

  it('ignores evidence when the original finding has none', async () => {
    scan.mockResolvedValue([mk({ evidence: 'whatever' })]);
    expect((await Verifier.verify(mk({ evidence: undefined }), { target: '/p' })).status).toBe('still-present');
  });

  it('does not treat a same-rule finding in a different file as still present', async () => {
    scan.mockResolvedValue([mk({ file: 'src/b.js' })]);
    expect((await Verifier.verify(mk({}), { target: '/p' })).status).toBe('fixed');
  });

  it('degrades to inconclusive (with the error message) when the re-scan throws', async () => {
    scan.mockRejectedValue(new Error('target vanished'));
    expect(await Verifier.verify(mk({}), { target: '/p' })).toEqual({ status: 'inconclusive', detail: 'target vanished' });
  });

  it('reports fixed on an empty re-scan', async () => {
    scan.mockResolvedValue([]);
    expect((await Verifier.verify(mk({}), { target: '/p' })).status).toBe('fixed');
  });
});

describe('Verifier: dynamic findings', () => {
  const dyn = (over: Partial<Finding> = {}) => mk({ source: 'dynamic', rule: 'cors-wildcard', endpoint: '/api/x', file: undefined, ...over });

  it('is inconclusive with guidance when there is no running-app context', async () => {
    const r = await Verifier.verify(dyn(), { target: '/p' });
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/No running app/);
    expect(find).not.toHaveBeenCalled();
  });

  it('refuses a non-loopback base URL without probing anything', async () => {
    const r = await Verifier.verify(dyn(), { target: '/p', dynamic: { baseUrl: 'http://example.com:3000', routes } });
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/non-loopback.*Nothing was re-checked/);
    expect(find).not.toHaveBeenCalled();
    expect(run).not.toHaveBeenCalled();
  });

  it('refuses an unparseable base URL', async () => {
    const r = await Verifier.verify(dyn(), { target: '/p', dynamic: { baseUrl: 'not a url', routes } });
    expect(r.status).toBe('inconclusive');
    expect(run).not.toHaveBeenCalled();
  });

  it('is inconclusive when the app is no longer reachable', async () => {
    find.mockResolvedValue(null);
    const r = await Verifier.verify(dyn(), { target: '/p', dynamic: { baseUrl: 'http://localhost:3456', routes } });
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/No local server is listening/);
    expect(find).toHaveBeenCalledWith([3456]);
    expect(run).not.toHaveBeenCalled();
  });

  it('defaults to port 80 when the base URL has no explicit port', async () => {
    find.mockResolvedValue(null);
    await Verifier.verify(dyn(), { target: '/p', dynamic: { baseUrl: 'http://127.0.0.1', routes } });
    expect(find).toHaveBeenCalledWith([80]);
  });

  it('is still-present when the same rule+endpoint is reported again', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    run.mockResolvedValue({ probed: ['/x'], endpoints: [], findings: [dyn({ proof: { request: "curl -i 'http://localhost:3000/api/x'", status: 200 } })] });
    const r = await Verifier.verify(dyn(), { target: '/p', dynamic: { baseUrl: 'http://localhost:3000', routes } });
    expect(r.status).toBe('still-present');
    expect(r.proof?.status).toBe(200);
    expect(run).toHaveBeenCalledWith('http://localhost:3000', routes, { aggressive: false });
  });

  it('is fixed when the rule is gone, or only fires on another endpoint', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    run.mockResolvedValue({
      probed: ['/x'],
      endpoints: [{ method: 'GET', path: '/api/x', status: 200 }],
      findings: [dyn({ endpoint: '/api/other' }), dyn({ rule: 'other' })],
    });
    const r = await Verifier.verify(dyn(), { target: '/p', dynamic: { baseUrl: 'http://localhost:3000', routes } });
    expect(r.status).toBe('fixed');
    expect(r.detail).toMatch(/control GET \/api\/x still answers HTTP 200/);
  });

  const live = { target: '/p', dynamic: { baseUrl: 'http://localhost:3000', routes } };

  it('is inconclusive (never fixed) when the endpoint did not answer the re-check', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    run.mockResolvedValue({ probed: ['/x'], endpoints: [{ method: 'GET', path: '/other', status: 200 }], findings: [] });
    const r = await Verifier.verify(dyn(), live);
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/did not answer.*not proof of a fix/);
  });

  it('is inconclusive when the endpoint now errors (5xx is not a fix)', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    run.mockResolvedValue({ probed: ['/x'], endpoints: [{ method: 'GET', path: '/api/x', status: 502 }, { method: 'GET', path: '/ok', status: 200 }], findings: [] });
    const r = await Verifier.verify(dyn(), live);
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/HTTP 502/);
  });

  it('needs a control on ANOTHER route for auth-bypass: a lone 401 could be an app rejecting everything', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    run.mockResolvedValue({ probed: ['/x'], endpoints: [{ method: 'GET', path: '/api/x', status: 401 }], findings: [] });
    const r = await Verifier.verify(dyn({ rule: 'auth-bypass' }), live);
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/no control request succeeded/i);
  });

  it('is fixed for auth-bypass when the endpoint now refuses and another route still answers 2xx', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    run.mockResolvedValue({
      probed: ['/x'],
      endpoints: [{ method: 'GET', path: '/api/x', status: 401 }, { method: 'GET', path: '/health', status: 200 }],
      findings: [],
    });
    const r = await Verifier.verify(dyn({ rule: 'auth-bypass' }), live);
    expect(r.status).toBe('fixed');
    expect(r.detail).toMatch(/now answers HTTP 401.*\/health/);
  });

  it('accepts the endpoint itself as control for content rules (e.g. secret-in-response)', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    run.mockResolvedValue({ probed: ['/x'], endpoints: [{ method: 'GET', path: '/api/x', status: 200 }], findings: [] });
    expect((await Verifier.verify(dyn({ rule: 'secret-in-response' }), live)).status).toBe('fixed');
  });

  it('is inconclusive when the re-check only produced a could-not-verify note', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    const note = dyn({ rule: 'missing-rate-limit', note: true, title: 'Rate limiting on /api/x could not be verified' });
    run.mockResolvedValue({ probed: ['/x'], endpoints: [{ method: 'GET', path: '/api/x', status: 200 }], findings: [note] });
    const r = await Verifier.verify(dyn({ rule: 'missing-rate-limit' }), live);
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/could not run/);
  });

  it('is inconclusive without probing when no routes were discovered (routes are never guessed)', async () => {
    const r = await Verifier.verify(dyn(), { target: '/p', dynamic: { baseUrl: 'http://localhost:3000', routes: [] } });
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/does not guess routes/);
    expect(find).not.toHaveBeenCalled();
    expect(run).not.toHaveBeenCalled();
  });

  it('is inconclusive (not fixed) when none of the discovered routes could be requested', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    run.mockResolvedValue({ probed: [], findings: [] });
    const r = await Verifier.verify(dyn(), { target: '/p', dynamic: { baseUrl: 'http://localhost:3000', routes } });
    expect(r.status).toBe('inconclusive');
    expect(r.detail).toMatch(/could not be re-checked/);
  });

  it('only enables the aggressive burst when re-checking the rate-limit rule', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    run.mockResolvedValue({ findings: [] });
    await Verifier.verify(dyn({ rule: 'missing-rate-limit' }), { target: '/p', dynamic: { baseUrl: 'http://localhost:3000', routes } });
    expect(run).toHaveBeenCalledWith('http://localhost:3000', routes, { aggressive: true });
  });

  it('degrades to inconclusive when the dynamic run throws', async () => {
    find.mockResolvedValue({ baseUrl: 'http://localhost:3000' });
    run.mockRejectedValue(new Error('socket hang up'));
    const r = await Verifier.verify(dyn(), { target: '/p', dynamic: { baseUrl: 'http://localhost:3000', routes } });
    expect(r).toEqual({ status: 'inconclusive', detail: 'socket hang up' });
  });
});
