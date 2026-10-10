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
  query(sql: string, params: readonly SqlValue[]): Promise<{ readonly rows: readonly SqlRow[] }>;
  /** discard=true when rollback/commit failed and connection cannot be trusted */
  release(discard: boolean): void | Promise<void>;
}
export interface ScopedSqlPool {
  connect(): Promise<ScopedSqlConnection>;
}
export interface SignedTransactionIssuer {
  sign(scope: AuthorizedReadScope, txid: string, expiry: number): Promise<string>;
}

const SELECT_SQL: Readonly<Record<ControlCollection, string>> = {
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
 * Acquire one connection; open one transaction; sign txid; SET LOCAL claims;
 * drop to the SQL reader role; run ONE fixed SELECT with bound values.
 * ROLLBACK + destroy connection on failure, including request cancellation.
 */
export async function readSignedScopedMetadata(
  pool: ScopedSqlPool,
  issuer: SignedTransactionIssuer,
  request: ScopedSqlRead,
  nowSeconds: () => number = () => Math.floor(Date.now() / 1000)
): Promise<readonly SqlRow[]> {
  const { scope, collection, signal } = request;
  const limit = request.limit ?? 50;
  if (!scope || !scopedIdentity(scope) ||
      !Object.prototype.hasOwnProperty.call(SELECT_SQL, collection) ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100 || signal?.aborted) {
    throw new Error('Invalid scoped read');
  }

  let connection: ScopedSqlConnection;
  try {
    connection = await pool.connect();
  } catch {
    throw new Error('Scoped metadata unavailable');
  }
  let started = false;
  let committed = false;
  let discard = false;
  try {
    if (signal?.aborted) throw new Error('Request cancelled');
    await connection.query('BEGIN', []);
    started = true;
    const assigned = await connection.query('SELECT txid_current()::text AS transaction_id', []);
    const txid = assigned.rows[0]?.transaction_id;
    if (typeof txid !== 'string' || !/^[0-9]{1,19}$/.test(txid)) {
      throw new Error('Missing database transaction ID');
    }

    const now = nowSeconds();
    if (!Number.isSafeInteger(now) || now < 1_000_000_000 ||
        now >= 9_999_999_900) throw new Error('Invalid clock');
    const expiry = now + 60;
    const mac = await issuer.sign(scope, txid, expiry);
    if (!/^[0-9a-f]{64}$/.test(mac)) throw new Error('Invalid signed scope');
    const claims: readonly [string, string][] = [
      ['saas.scope_actor', scope.actorId],
      ['saas.scope_tenant', scope.tenantId],
      ['saas.scope_txid', txid],
      ['saas.scope_expiry', String(expiry)],
      ['saas.scope_mac', mac],
    ];
    for (const [name, value] of claims) {
      if (signal?.aborted) throw new Error('Request cancelled');
      await connection.query('SELECT set_config($1::text, $2::text, true)', [name, value]);
    }
    // A real DB user must have a narrowly delegated SET ROLE permission;
    // do not connect as a superuser or grant access to signing tables.
    await connection.query('SET LOCAL ROLE saas_rls_reader', []);
    if (signal?.aborted) throw new Error('Request cancelled');
    const result = await connection.query(SELECT_SQL[collection], [scope.tenantId, limit]);
    if (signal?.aborted || !Array.isArray(result.rows) || result.rows.length > limit) {
      throw new Error('Invalid scoped database response');
    }
    // Whitelist again; neither accidental extra SQL columns nor driver
    // metadata can leak from this internal proof-of-concept.
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
    if (signal?.aborted) throw new Error('Request cancelled');
    await connection.query('COMMIT', []);
    committed = true;
    return safe;
  } catch {
    discard = true;
    if (started && !committed) {
      try {
        await connection.query('ROLLBACK', []);
      } catch {
        // Connection will be destroyed, not returned to the pool.
      }
    }
    throw new Error('Scoped metadata unavailable');
  } finally {
    try {
      await connection.release(discard);
    } catch {
      throw new Error('Scoped metadata unavailable');
    }
  }
}
