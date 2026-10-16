import type { ServerAuthorizationRevisionSource } from './authorizationRevision';
import { AuthorizationRevisionDenied } from './authorizationRevision';
import {
  readSignedScopedAuthorizationRevision, ScopedSqlAuthorizationDenied,
  type ScopedSqlPool, type SignedTransactionIssuer,
} from './signedSqlBoundary';

/**
 * 2G.4d.3 — staging-only adapter. Uses the same signed transaction,
 * explicit PostgreSQL membership gate, HMAC, cancellation and whole-pool
 * quarantine as existing RLS metadata. Requires migration 004.
 *
 * Production physical-connection discard, cross-instance revocation
 * linearizability, OIDC and a real HTTP backend remain UNIMPLEMENTED.
 */
export function createSignedPgAuthorizationRevisionSource(
  pool: ScopedSqlPool,
  signer: SignedTransactionIssuer
): ServerAuthorizationRevisionSource {
  return {
    async readRevision(scope, collection, signal) {
      try {
        return await readSignedScopedAuthorizationRevision(pool, signer, {
          scope, collection, signal,
        });
      } catch (error) {
        if (error instanceof ScopedSqlAuthorizationDenied) {
          throw new AuthorizationRevisionDenied();
        }
        // The high-level boundary converts all other failures to a generic
        // 503 and tenantless audit. Never expose signer/driver error details.
        throw error;
      }
    },
  };
}
