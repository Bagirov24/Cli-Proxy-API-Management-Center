import type { AuthorizedReadScope, ControlCollection, TenantRole } from '../contracts';

/**
 * Stage 2E SQL query boundary (SPEC / isolated fixtures).
 * No pg driver is installed, no deployment or live connection is created.
 * The caller MUST verify issuer/subject, tenant membership and RBAC first.
 * Only server-defined SQL templates can be executed; no raw client SQL.
 */
export type SqlValue = string | number;
export type SqlRow = Readonly<Record<string, unknown>>;

export interface ScopedSqlConnection {
  /** Query cancellation MUST signal the active driver operation, not just the caller. */
  query(sql: string, params: readonly SqlValue[], signal?: AbortSignal): Promise<{ readonly rows: readonly SqlRow[] }>;
  /** On discard, NEVER return the physical connection to another tenant. */
  release(discard: boolean): void | Promise<void>;
}
export type SqlPoolQuarantineReason = 'acquire-uncertain' | 'read-failed' | 'release-uncertain';
export interface ScopedSqlPool {
  /** Cancellation while waiting for a reserved pool connection. */
  connect(signal?: AbortSignal): Promise<ScopedSqlConnection>;
  /** Synchronous barrier: block ALL future reservations before any async cleanup.
   * A broken/unknown connection requires a quarantined pool, not silent reuse.
   * The test driver closes its entire pool; a production driver needs a proved
   * physical connection discard protocol, cancellation and network-failure QA. */
  quarantine(reason: SqlPoolQuarantineReason): void;
}
export interface SignedTransactionIssuer {
  sign(scope: AuthorizedReadScope, txid: string, expiry: number): Promise<string>;
}

/** Exact, server-owned SQL templates; may be used for staging driver allowlisting. */
export const CONTROL_READ_SELECT_SQL: Readonly<Record<ControlCollection, string>> = {
  tenant: 'SELECT id, name, status FROM saas_rls.tenants WHERE id = $1 ORDER BY id LIMIT $2',
  projects: 'SELECT id, tenant_id, name, status FROM saas_rls.projects WHERE tenant_id = $1 ORDER BY id LIMIT $2',
  applications: 'SELECT id, tenant_id, project_id, name, status FROM saas_rls.applications WHERE tenant_id = $1 ORDER BY id LIMIT $2',
  'client-keys': "SELECT id, application_id, key_kind, status FROM saas_rls.key_bindings WHERE tenant_id = $1 AND key_kind = 'cpa' ORDER BY id LIMIT $2",
  accounts: "SELECT id, kind, owner_kind, owner_tenant_id, status FROM saas_rls.resource_catalog WHERE kind = 'account' AND saas_rls.scope_tenant() = $1 ORDER BY id LIMIT $2",
  pools: "SELECT id, kind, owner_kind, owner_tenant_id, status FROM saas_rls.resource_catalog WHERE kind = 'pool' AND saas_rls.scope_tenant() = $1 ORDER BY id LIMIT $2",
  egress: "SELECT id, kind, owner_kind, owner_tenant_id, status FROM saas_rls.resource_catalog WHERE kind = 'egress' AND saas_rls.scope_tenant() = $1 ORDER BY id LIMIT $2",
  routing: 'SELECT id, application_id, key_binding_id, pool_id, provider_id, requested_model_id, status, egress_policy FROM saas_rls.routing_bindings WHERE tenant_id = $1 ORDER BY id LIMIT $2',
};

const FIELDS: Readonly<Record<ControlCollection, readonly string[]>> = {
  tenant: ['id', 'name', 'status'],
  projects: ['id', 'tenant_id', 'name', 'status'],
  applications: ['id', 'tenant_id', 'project_id', 'name', 'status'],
  'client-keys': ['id', 'application_id', 'key_kind', 'status'],
  accounts: ['id', 'kind', 'owner_kind', 'owner_tenant_id', 'status'],
  pools: ['id', 'kind', 'owner_kind', 'owner_tenant_id', 'status'],
  egress: ['id', 'kind', 'owner_kind', 'owner_tenant_id', 'status'],
  routing: ['id', 'application_id', 'key_binding_id', 'pool_id', 'provider_id',
    'requested_model_id', 'status', 'egress_policy'],
};

export interface ScopedSqlRead {
  readonly scope: AuthorizedReadScope;
  readonly collection: ControlCollection;
  readonly limit?: number;
  readonly signal?: AbortSignal;
  /** Backend-owned wall-clock deadline; includes acquire, signing and SQL. */
  readonly timeoutMs?: number;
  /** Upper bound per cleanup operation; does NOT certify physical disconnect. */
  readonly cleanupTimeoutMs?: number;
}

function scopedIdentity(scope: AuthorizedReadScope): boolean {
  const roles: readonly TenantRole[] = [
    'tenant-owner', 'tenant-admin', 'tenant-viewer', 'tenant-auditor',
  ];
  return /^[A-Za-z0-9_-]{1,128}$/.test(scope.actorId) &&
    /^[A-Za-z0-9_-]{1,64}$/.test(scope.tenantId) &&
    roles.includes(scope.role) &&
    /^[A-Za-z0-9_-]{1,128}$/.test(scope.correlationId);
}

/** Only the trusted, pre-provisioned signer receives the HMAC key. */
export function createPinnedHmacScopeIssuer(key: CryptoKey): SignedTransactionIssuer {
  if (key.type !== 'secret' || key.algorithm.name !== 'HMAC' ||
      (key.algorithm as HmacKeyAlgorithm).hash.name !== 'SHA-256' ||
      !key.usages.includes('sign')) {
    throw new Error('Invalid signed-scope issuer configuration');
  }
  return {
    async sign(scope, txid, expiry) {
      if (!scopedIdentity(scope) || !/^[0-9]{1,19}$/.test(txid) ||
          !Number.isSafeInteger(expiry) || expiry < 1_000_000_000 ||
          expiry > 9_999_999_999) {
        throw new Error('Invalid signed-scope input');
      }
      // Matches PostgreSQL concat_ws(chr(31), actor, tenant, txid, expiry).
      const payload = [scope.actorId, scope.tenantId, txid, String(expiry)].join('\x1f');
      const digest = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
      return Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, '0')).join('');
    },
  };
}

/**
 * Observed cancellation is bounded even when a driver ignores its signal.
 * In-flight promises are still observed so delayed rejection cannot escape as
 * an unhandled error; an unsafe connection MUST be quarantined before cleanup.
 */
function waitForAbort<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new Error('Scoped SQL cancelled'));
  return new Promise<T>((resolve, reject) => {
    let finished = false;
    const detach = () => {
      if (finished) return false;
      finished = true;
      signal.removeEventListener('abort', onAbort);
      return true;
    };
    const onAbort = () => {
      if (detach()) reject(new Error('Scoped SQL cancelled'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
    pending.then(
      (value) => { if (detach()) resolve(value); },
      (error: unknown) => { if (detach()) reject(error); }
    );
  });
}

async function boundedCleanup(
  operation: () => void | Promise<unknown>,
  timeoutMs: number
): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      Promise.resolve().then(operation),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('SQL cleanup timeout')), timeoutMs);
      }),
    ]);
    return true;
  } catch {
    return false;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * One reserved connection, one transaction and one fixed SELECT.
 * On ANY uncertain state, synchronously quarantine the pool before bounded
 * cleanup. A timed-out SQL statement may still run inside a broken driver:
 * never assume Promise.race cancelled it or that ROLLBACK is safe concurrently.
 *
 * CONTRACT ONLY: safe production use requires independently verified driver
 * quarantine/discard semantics and database-enforced statement timeouts.
 */
export async function readSignedScopedMetadata(
  pool: ScopedSqlPool,
  issuer: SignedTransactionIssuer,
  request: ScopedSqlRead,
  nowSeconds: () => number = () => Math.floor(Date.now() / 1000)
): Promise<readonly SqlRow[]> {
  const { scope, collection, signal } = request;
  const limit = request.limit ?? 50;
  const timeoutMs = request.timeoutMs ?? 15_000;
  const cleanupMs = request.cleanupTimeoutMs ?? 1_000;
  if (!scope || !scopedIdentity(scope) ||
      !Object.prototype.hasOwnProperty.call(CONTROL_READ_SELECT_SQL, collection) ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 60_000 ||
      !Number.isSafeInteger(cleanupMs) || cleanupMs < 10 || cleanupMs > 5_000 ||
      signal?.aborted || typeof pool.quarantine !== 'function') {
    throw new Error('Invalid scoped read');
  }

  // A single backend-owned signal reaches reserve() and every SQL operation;
  // caller cancellation and the wall-clock deadline both abort the driver.
  const controller = new AbortController();
  const forwardAbort = () => controller.abort();
  signal?.addEventListener('abort', forwardAbort, { once: true });
  if (signal?.aborted) forwardAbort();
  const timer = setTimeout(forwardAbort, timeoutMs);
  const quarantine = (reason: SqlPoolQuarantineReason) => {
    // The pool MUST synchronously mark itself unusable before returning.
    // Failure of a supplied pool implementation is still a generic denial.
    try { pool.quarantine(reason); } catch { /* adapter is not safe */ }
  };

  let connection: ScopedSqlConnection | undefined;
  let acquireAbandoned = false;
  let started = false;
  let committed = false;
  let activeQueries = 0;
  let discard = false;
  try {
    // A driver can ignore abort while waiting for capacity. If it returns a
    // reservation AFTER the deadline, discard that late reservation as well.
    const acquiring = Promise.resolve().then(() => pool.connect(controller.signal));
    void acquiring.then((late) => {
      if (acquireAbandoned) {
        quarantine('acquire-uncertain');
        void boundedCleanup(() => late.release(true), cleanupMs);
      }
    }, () => { /* already rejected and observed by waitForAbort */ });
    try {
      connection = await waitForAbort(acquiring, controller.signal);
    } catch {
      acquireAbandoned = true;
      quarantine('acquire-uncertain');
      throw new Error('Scoped metadata unavailable');
    }

    const reserved = connection;
    const query = (sql: string, params: readonly SqlValue[]) => {
      if (controller.signal.aborted) throw new Error('Scoped SQL cancelled');
      activeQueries += 1;
      const pending = Promise.resolve().then(() => {
        if (controller.signal.aborted) throw new Error('Scoped SQL cancelled');
        return reserved.query(sql, params, controller.signal);
      });
      void pending.then(
        () => { activeQueries -= 1; },
        () => { activeQueries -= 1; }
      );
      return waitForAbort(pending, controller.signal);
    };

    let output: readonly SqlRow[] = [];
    let releaseFailed = false;
    try {
      if (controller.signal.aborted) throw new Error('Scoped SQL cancelled');
      await query('BEGIN', []);
      started = true;
      const assigned = await query('SELECT txid_current()::text AS transaction_id', []);
      const txid = assigned.rows[0]?.transaction_id;
      if (typeof txid !== 'string' || !/^[0-9]{1,19}$/.test(txid)) {
        throw new Error('Missing database transaction ID');
      }
      const now = nowSeconds();
      if (!Number.isSafeInteger(now) || now < 1_000_000_000 ||
          now >= 9_999_999_900) throw new Error('Invalid clock');
      const expiry = now + 60;
      const mac = await waitForAbort(issuer.sign(scope, txid, expiry), controller.signal);
      if (!/^[0-9a-f]{64}$/.test(mac)) throw new Error('Invalid signed scope');
      const claims: readonly [string, string][] = [
        ['saas.scope_actor', scope.actorId],
        ['saas.scope_tenant', scope.tenantId],
        ['saas.scope_txid', txid],
        ['saas.scope_expiry', String(expiry)],
        ['saas.scope_mac', mac],
      ];
      for (const [name, value] of claims) {
        await query('SELECT set_config($1::text, $2::text, true)', [name, value]);
      }
      await query('SET LOCAL ROLE saas_rls_reader', []);
      const result = await query(CONTROL_READ_SELECT_SQL[collection], [scope.tenantId, limit]);
      if (controller.signal.aborted || !Array.isArray(result.rows) || result.rows.length > limit) {
        throw new Error('Invalid scoped database response');
      }
      const safe = result.rows.map((item) => {
        if (!item || typeof item !== 'object' || Array.isArray(item)) {
          throw new Error('Invalid row shape');
        }
        const row: Record<string, unknown> = {};
        for (const field of FIELDS[collection]) {
          const value = item[field];
          if (value !== null && (typeof value !== 'string' || value.length > 256)) {
            throw new Error('Invalid row field');
          }
          row[field] = value;
        }
        if (typeof row.id !== 'string' || row.id.length === 0 ||
            ('tenant_id' in row && row.tenant_id !== scope.tenantId)) {
          throw new Error('Cross-tenant or malformed database row');
        }
        return row;
      });
      if (controller.signal.aborted) throw new Error('Scoped SQL cancelled');
      await query('COMMIT', []);
      committed = true;
      if (controller.signal.aborted) throw new Error('Scoped SQL cancelled');
      output = safe;
    } catch {
      discard = true;
      quarantine('read-failed');
      // Never issue ROLLBACK concurrently with a possibly still-running
      // BEGIN/SELECT/COMMIT on the same socket. A driver that ignores cancel
      // must be destroyed, not returned to a tenant's reservation queue.
      if (started && !committed && activeQueries === 0) {
        await boundedCleanup(
          () => reserved.query('ROLLBACK', [], AbortSignal.timeout(cleanupMs)),
          cleanupMs
        );
      }
      throw new Error('Scoped metadata unavailable');
    } finally {
      const released = await boundedCleanup(() => reserved.release(discard), cleanupMs);
      if (!released) {
        quarantine('release-uncertain');
        releaseFailed = true;
      }
    }
    if (releaseFailed) throw new Error('Scoped metadata unavailable');
    return output;
  } catch {
    throw new Error('Scoped metadata unavailable');
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', forwardAbort);
  }
}
