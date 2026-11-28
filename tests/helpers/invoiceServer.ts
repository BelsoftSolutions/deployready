/**
 * A real loopback HTTP API with two users who each own one private invoice.
 * Used by the authorization-audit tests: every scenario is a small change in how
 * the server answers a caller who asks for an invoice that is not theirs.
 */
import * as http from 'http';
import type { AddressInfo } from 'net';

export type InvoiceMode =
  | 'leak' // returns anyone's invoice to any authenticated caller
  | 'deny-403'
  | 'deny-404'
  | 'leak-volatile' // leak, and every response carries a fresh requestId/timestamp
  | 'partial-leak' // foreign caller gets a subset of the owner's private fields
  | 'ignore-id' // ignores the requested id, returns the caller's own invoice
  | 'echo-error' // 200 {"error":"not found","id":"<requested>"} for foreign ids
  | 'echo-requested' // 200 {"requested":"<requested>"}; the owner has no invoice here (404)
  | '404-with-data'; // 404 status, but the body carries the owner's invoice

const SIG = 'loopbackTestSignature0001';

export function makeToken(claims: object): string {
  const seg = (o: object) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
  return `${seg({ alg: 'HS256', typ: 'JWT' })}.${seg(claims)}.${SIG}`;
}

export const ALICE = makeToken({ sub: 'alice' });
export const BOB = makeToken({ sub: 'bob' });

const INVOICES: Record<string, Record<string, unknown>> = {
  alice: {
    invoiceId: 'inv_1001',
    owner: 'alice',
    customer: { name: 'Alice Anders', email: 'alice@example.test', address: '1 Apple Way' },
    amount: 1250.5,
    currency: 'EUR',
    status: 'paid',
    items: [
      { sku: 'A-1', qty: 2 },
      { sku: 'A-2', qty: 1 },
    ],
    notes: 'deliver to back door',
  },
  bob: {
    invoiceId: 'inv_2002',
    owner: 'bob',
    customer: { name: 'Bob Brown', email: 'bob@example.test', address: '9 Birch Road' },
    amount: 8730.25,
    currency: 'EUR',
    status: 'paid',
    items: [
      { sku: 'B-7', qty: 5 },
      { sku: 'B-9', qty: 3 },
    ],
    notes: 'VIP customer, call before shipping',
  },
};

function caller(req: http.IncomingMessage): string | null {
  const auth = req.headers.authorization ?? '';
  const token = auth.replace(/^Bearer\s+/, '');
  const parts = token.split('.');
  if (parts.length !== 3 || parts[2] !== SIG) return null;
  try {
    const p = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as { sub?: string };
    return typeof p.sub === 'string' ? p.sub : null;
  } catch {
    return null;
  }
}

export interface InvoiceServer {
  baseUrl: string;
  /** Every request the server received (method + path + whether it carried auth). */
  log: { method: string; path: string; auth: boolean }[];
  setMode(mode: InvoiceMode): void;
  close(): Promise<void>;
}

export async function startInvoiceServer(initial: InvoiceMode = 'leak'): Promise<InvoiceServer> {
  let mode: InvoiceMode = initial;
  let counter = 0;
  const log: InvoiceServer['log'] = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    log.push({ method: req.method ?? 'GET', path: url.pathname, auth: Boolean(req.headers.authorization) });
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    const who = caller(req);
    if (!who) return send(401, { error: 'unauthorized' });
    const m = /^\/api\/users\/([^/]+)\/invoice$/.exec(url.pathname);
    if (!m) return send(404, { error: 'no such route' });
    const requested = decodeURIComponent(m[1]!);
    const own = requested === who;
    const invoice = INVOICES[requested];
    counter++;
    const meta = { requestId: `req-${counter}-${Math.random().toString(36).slice(2, 8)}`, servedAt: new Date(Date.now() + counter).toISOString() };

    switch (mode) {
      case 'leak':
        return invoice ? send(200, invoice) : send(404, { error: 'not found' });
      case 'leak-volatile':
        return invoice ? send(200, { meta, invoice }) : send(404, { error: 'not found', meta });
      case 'deny-403':
        return own && invoice ? send(200, invoice) : send(403, { error: 'forbidden' });
      case 'deny-404':
        return own && invoice ? send(200, invoice) : send(404, { error: 'not found' });
      case 'partial-leak':
        if (own) return send(200, invoice);
        // A "summary" view that forgot the ownership check: only a few fields.
        return send(200, { invoiceId: invoice?.invoiceId, contact: (invoice?.customer as { email: string }).email, status: invoice?.status });
      case 'ignore-id':
        return send(200, INVOICES[who]);
      case 'echo-error':
        return own ? send(200, invoice) : send(200, { error: 'not found', id: requested });
      case 'echo-requested':
        if (who === 'bob') return send(404, { error: 'you have no invoice on this route' });
        return own ? send(200, invoice) : send(200, { requested });
      case '404-with-data':
        return own ? send(200, invoice) : send(404, { error: 'not found', debug: invoice });
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    log,
    setMode: (m) => {
      mode = m;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
