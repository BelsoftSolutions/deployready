/**
 * Independent-audit reproduction (0.4.0 → 0.5): two users with private invoices
 * on a REAL loopback HTTP server, probed through the real active adapter.
 *
 * 0.4.0 results (whole-response equality), recorded before the fix:
 *   leak                   → broken        (correct)
 *   deny-403 / deny-404    → denied        (correct)
 *   leak-volatile          → inconclusive  (WRONG: changing requestId/timestamp)
 *   partial-leak           → inconclusive  (WRONG: subset of private fields)
 *   ignore-id              → inconclusive  (own data; should be safe with an explanation)
 *   echo-requested         → broken        (FALSE POSITIVE: only the requested id echoed)
 *   echo-error             → inconclusive  (harmless 200 error echoing the id)
 *   404-with-data          → denied        (FALSE NEGATIVE: 404 body carries the owner's invoice)
 */
import { startInvoiceServer, ALICE, BOB, type InvoiceMode, type InvoiceServer } from './helpers/invoiceServer';
import { runActiveScan, type ActiveObservation } from '../src/active/runner';
import { createActiveHttpAdapter } from '../src/active/httpAdapter';
import { planActiveRequests } from '../src/active/requestPlan';
import type { AuthzVerdict } from '../src/active/accessControl';
import type { Route } from '../src/types';

const invoiceRoute: Route = { method: 'GET', path: '/api/users/:id/invoice', file: 'api.js', guarded: true };

let server: InvoiceServer;
beforeAll(async () => {
  server = await startInvoiceServer();
});
afterAll(async () => {
  await server.close();
});

async function probe(mode: InvoiceMode) {
  server.setMode(mode);
  const seen: ActiveObservation[] = [];
  const requests = planActiveRequests([invoiceRoute], { sub: 'alice' }).requests;
  const findings = await runActiveScan(
    { token: ALICE, tokenB: BOB, requests, baseUrl: server.baseUrl, onObserve: (o) => seen.push(o) },
    createActiveHttpAdapter({ baseUrl: server.baseUrl }),
  );
  const cross = seen.find((o): o is Extract<ActiveObservation, { kind: 'cross' }> => o.kind === 'cross');
  return { findings: findings.filter((f) => f.rule === 'bola-idor'), cross: cross! };
}

const EXPECTED: [InvoiceMode, AuthzVerdict, string][] = [
  ['leak', 'confirmed-vulnerable', 'A reads B’s invoice'],
  ['deny-403', 'verified-denied', 'protected 403'],
  ['deny-404', 'verified-denied', 'protected 404'],
  ['leak-volatile', 'confirmed-vulnerable', 'leak with changing response metadata'],
  ['partial-leak', 'confirmed-vulnerable', 'partial private-field disclosure'],
  ['ignore-id', 'verified-denied', 'server ignores the swapped id and returns own data'],
  ['echo-error', 'verified-denied', 'harmless {"error":"not found","id":<B>} echo'],
  ['echo-requested', 'inconclusive', 'harmless {"requested":<B>} echo, owner has no invoice'],
  ['404-with-data', 'confirmed-vulnerable', 'HTTP 404 whose body contains B’s private data'],
];

describe('authorization audit: semantic verdicts against a real loopback API', () => {
  it.each(EXPECTED)('%s → %s (%s)', async (mode, verdict) => {
    const { findings, cross } = await probe(mode);
    expect(cross.verdict).toBe(verdict);
    expect(findings).toHaveLength(verdict === 'confirmed-vulnerable' ? 1 : 0);
    if (verdict === 'confirmed-vulnerable') expect(findings[0]!.severity).toBe('critical');
  });

  it('explains what was disclosed, why, and how, without the raw private values or tokens', async () => {
    const { findings } = await probe('partial-leak');
    const f = findings[0]!;
    expect(f.description).toMatch(/customer\.email \(sensitive\) = b\*\*\*@e\*\*\*\.test/);
    expect(f.description).toMatch(/Why this violates the policy/);
    expect(f.description).toMatch(/How it was established: Compared field by field against 2 owner baselines/);
    expect(f.description).toMatch(/anonymous control \(no credentials\): HTTP 401/);
    const all = JSON.stringify(f);
    expect(all).not.toContain('bob@example.test');
    expect(all).not.toContain(ALICE);
    expect(all).not.toContain(BOB);
    expect(f.proof!.request).toMatch(/--oauth2-bearer "\$TOKEN" '.*\/api\/users\/bob\/invoice'/);
    expect(f.proof!.control).toMatch(/\$TOKEN_B/);
  });

  it('a 404 leak says the status code is not proof', async () => {
    const { findings } = await probe('404-with-data');
    expect(findings[0]!.description).toMatch(/HTTP 404.*status codes are not proof/);
    expect(findings[0]!.proof!.status).toBe(404);
  });

  it('volatile fields are named in the explanation', async () => {
    const { findings } = await probe('leak-volatile');
    expect(findings[0]!.description).toMatch(/ignored volatile\/configured fields: .*meta\.requestId/);
  });
});
