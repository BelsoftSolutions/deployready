/**
 * Report shapes of the policy-driven authorization matrix (0.6). Kept in their
 * own module so `src/types.ts` only references them.
 */

/** Outcome of one (resource, identity, action) cell. */
export type AuthzCellVerdict = 'allowed-as-expected' | 'denied-as-expected' | 'violation' | 'inconclusive' | 'untested';

export const AUTHZ_VERDICTS: readonly AuthzCellVerdict[] = ['violation', 'inconclusive', 'untested', 'allowed-as-expected', 'denied-as-expected'];

/** Which kind of test produced a cell. */
export type AuthzTestClass =
  | 'missing-auth' // anonymous on a non-public route
  | 'vertical' // a role on a route reserved for other roles (BFLA)
  | 'horizontal' // another user's record (BOLA/IDOR)
  | 'cross-tenant' // a record of another tenant
  | 'nested-id' // own parent id + another user's child id (/orgs/:mine/projects/:theirs)
  | 'list-filter' // a list route that includes other users' records
  | 'batch' // an ids array that mixes own and foreign ids
  | 'export' // an export / download route
  | 'cross-write' // change another identity's record (stateful)
  | 'cross-delete' // delete another identity's record (stateful)
  | 'mass-assignment' // extra fields stored on create/update (stateful)
  | 'privilege-escalation' // a role/admin field accepted on the identity's own record (stateful)
  | 'graphql-introspection'
  | 'graphql-id'
  | 'own-access'; // the identity on its own record (the control)

export interface AuthzCell {
  resource: string;
  /** Policy route, e.g. "GET /api/invoices/:id". */
  route: string;
  identity: string;
  role: string;
  action: 'read' | 'write';
  testClass: AuthzTestClass;
  /** Owner of the record that was requested, when it is another identity. */
  target?: string;
  expected: 'allow' | 'deny';
  verdict: AuthzCellVerdict;
  /** Why this verdict (what was observed). */
  reason: string;
  /** Plain-English statement of a violation ("User alice could read invoices of bob…"). */
  statement?: string;
  /** Concrete request (method + path), never a credential. */
  request?: string;
  /** Finding id that reports this violation. */
  findingId?: string;
}

export interface AuthzIdentitySummary {
  name: string;
  role: string;
  tenant?: string;
  available: boolean;
  reason?: string;
}

export interface AuthzMatrix {
  /** Where the policy came from. */
  policySource: string;
  safetyLevel: string;
  identities: AuthzIdentitySummary[];
  cells: AuthzCell[];
  summary: Record<AuthzCellVerdict, number>;
  /** Discovered routes that no policy resource covers (so they were not tested by the matrix). */
  uncoveredRoutes: string[];
  /** Requests actually sent. */
  requestsSent: number;
  /** Config problems that were ignored (bad entries). */
  problems?: string[];
}
