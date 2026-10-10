import { beforeAll, describe, expect, test } from 'bun:test';
import {
  createPinnedHmacScopeIssuer, readSignedScopedMetadata,
  type ScopedSqlConnection, type ScopedSqlPool, type SignedTransactionIssuer,
  type SqlRow, type SqlValue,
} from '../src/features/saasBlueprint/controlApi/server/signedSqlBoundary';
import type { AuthorizedReadScope, ControlCollection } from '../src/features/saasBlueprint/controlApi/contracts';

const scope: AuthorizedReadScope = {
  actorId: 'actor-north', tenantId: 'demo-north', role: 'tenant-admin',
  correlationId: 'server-trace',
};
const now = 1_800_000_000;
let signer: SignedTransactionIssuer;

type Call = { sql: string; params: readonly SqlValue[] };
function harness(rows: readonly SqlRow[] = [
  { id: 'project-north', tenant_id: 'demo-north',
    name: 'North Project', status: 'active', hidden_token: 'NEVER_RETURN' },
]) {
  const calls: Call[] = [];
  const releases: boolean[] = [];
  const quarantines: string[] = [];
  let failAt: string | null = null;
  let afterCall: ((sql: string) => void) | null = null;
  const conn: ScopedSqlConnection = {
    async query(sql, params) {
      calls.push({ sql, params });
      if (failAt && sql.includes(failAt)) throw new Error('DATABASE_INTERNAL_SECRET');
      if (afterCall) afterCall(sql);
      if (sql.includes('txid_current')) {
        return { rows: [{ transaction_id: '123456789' }] };
      }
      if (sql.startsWith('SELECT id, ')) return { rows };
      return { rows: [] };
    },
    release(discard) { releases.push(discard); },
  };
  const pool: ScopedSqlPool = {
    async connect() { return conn; },
    quarantine(reason) { quarantines.push(reason); },
  };
  return { calls, releases, quarantines, pool,
    failWhen: (sql: string) => { failAt = sql; },
    onQuery: (fn: (sql: string) => void) => { afterCall = fn; } };
}

beforeAll(async () => {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', secret, {
    name: 'HMAC', hash: 'SHA-256',
  }, false, ['sign']);
  signer = createPinnedHmacScopeIssuer(key);
});

describe('Stage 2E — signed SQL scoped query boundary (fake pool, no network)', () => {
  test('binds scoped tenant and fixed LIMIT without interpolating SQL', async () => {
    const h = harness();
    const rows = await readSignedScopedMetadata(h.pool, signer, {
      scope, collection: 'projects', limit: 10,
    }, () => now);
    expect(rows).toEqual([
      { id: 'project-north', tenant_id: 'demo-north',
        name: 'North Project', status: 'active' },
    ]);
    expect(h.calls[0]).toEqual({ sql: 'BEGIN', params: [] });
    expect(h.calls[1].sql).toContain('txid_current');
    expect(h.calls.filter((call) => call.sql.includes('set_config')).length).toBe(5);
    expect(h.calls.find((call) => call.sql.startsWith('SELECT id, '))).toMatchObject({
      params: ['demo-north', 10],
    });
    expect(h.calls.at(-1)).toEqual({ sql: 'COMMIT', params: [] });
    expect(h.releases).toEqual([false]);
    const allStatements = h.calls.map((call) => call.sql).join('\n');
    expect(allStatements).not.toContain('actor-north');
    expect(allStatements).not.toContain('demo-north');
    expect(allStatements).toContain('SET LOCAL ROLE saas_rls_reader');
  });

  test('signs compatible actor, tenant, tx ID and expiry in lower-case hex', async () => {
    const mac = await signer.sign(scope, '123456789', now + 60);
    expect(mac).toMatch(/^[0-9a-f]{64}$/);
    expect(await signer.sign({ ...scope, tenantId: 'demo-orbit' },
      '123456789', now + 60)).not.toBe(mac);
    expect(await signer.sign(scope, '123456790', now + 60)).not.toBe(mac);
  });

  test('rejects invalid scope, unsafe collection, limit and cancellation before connecting', async () => {
    const h = harness();
    const cases = [
      { scope: { ...scope, tenantId: "demo-north'; SELECT 1 --" }, collection: 'projects' },
      { scope, collection: 'other' as ControlCollection },
      { scope, collection: '__proto__' as ControlCollection },
      { scope, collection: 'projects' as const, limit: 10_000 },
      { scope, collection: 'projects' as const, limit: -1 },
    ];
    for (const input of cases) {
      await expect(readSignedScopedMetadata(h.pool, signer, input, () => now)).rejects.toThrow();
    }
    const controller = new AbortController();
    controller.abort();
    await expect(readSignedScopedMetadata(h.pool, signer, {
      scope, collection: 'projects', signal: controller.signal,
    }, () => now)).rejects.toThrow();
    expect(h.calls).toEqual([]);
  });

  test('errors roll back and discard connection with no upstream exception details', async () => {
    const h = harness();
    h.failWhen('SELECT id, ');
    const error = readSignedScopedMetadata(h.pool, signer, {
      scope, collection: 'projects',
    }, () => now);
    await expect(error).rejects.toThrow('Scoped metadata unavailable');
    expect(h.calls.at(-1)?.sql).toBe('ROLLBACK');
    expect(h.releases).toEqual([true]);
  });

  test('malformed rows and cross-tenant results are denied, never returned', async () => {
    for (const row of [
      { id: 'project-orbit', tenant_id: 'demo-orbit', name: 'Orbit', status: 'active' },
      { id: 'p', tenant_id: 'demo-north', name: 42, status: 'active' },
      { id: 'p', tenant_id: 'demo-north', name: 'N', status: undefined },
    ]) {
      const h = harness([row]);
      await expect(readSignedScopedMetadata(h.pool, signer, {
        scope, collection: 'projects',
      }, () => now)).rejects.toThrow('Scoped metadata unavailable');
      expect(h.releases).toEqual([true]);
    }
  });

  test('rechecks abort after asynchronous SQL and never commits cancelled data', async () => {
    const ctrl = new AbortController();
    const h = harness();
    h.onQuery((sql) => {
      if (sql.startsWith('SELECT id, ')) ctrl.abort();
    });
    await expect(readSignedScopedMetadata(h.pool, signer, {
      scope, collection: 'projects', signal: ctrl.signal,
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(h.calls.some((item) => item.sql === 'COMMIT')).toBe(false);
    // Cancellation may race an in-flight SELECT: never issue ROLLBACK on
    // the same socket until the driver confirms that query has stopped.
    expect(h.quarantines).toEqual(['read-failed']);
    expect(h.releases).toEqual([true]);
  });

  test('passes AbortSignal to connection acquisition for waiting reservations', async () => {
    const controller = new AbortController();
    let forwarded: AbortSignal | undefined;
    const pool: ScopedSqlPool = {
      async connect(signal) {
        forwarded = signal;
        throw new Error('SYNTHETIC_POOL_DRIVER_DETAILS');
      },
      quarantine() {},
    };
    await expect(readSignedScopedMetadata(pool, signer, {
      scope, collection: 'projects', signal: controller.signal,
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(forwarded).toBeDefined();
    expect(forwarded).not.toBe(controller.signal);
  });

  test('cancellation during COMMIT discards connection and cannot return stale rows', async () => {
    const controller = new AbortController();
    const h = harness();
    h.onQuery((sql) => {
      if (sql === 'COMMIT') controller.abort();
    });
    await expect(readSignedScopedMetadata(h.pool, signer, {
      scope, collection: 'projects', signal: controller.signal,
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(h.calls.some((call) => call.sql === 'COMMIT')).toBe(true);
    expect(h.releases).toEqual([true]);
  });


  test('hung SQL query hits deadline, quarantines before discard and does not commit', async () => {
    const events: string[] = [];
    let queryStarted = false;
    const connection: ScopedSqlConnection = {
      async query(sql) {
        if (sql === 'BEGIN') return { rows: [] };
        if (sql.includes('txid_current')) return { rows: [{ transaction_id: '123456789' }] };
        if (sql.startsWith('SELECT id, ')) {
          queryStarted = true;
          return new Promise(() => {}); // deliberately ignores AbortSignal
        }
        return { rows: [] };
      },
      release(discard) { events.push('release:' + discard); },
    };
    const pool: ScopedSqlPool = {
      async connect() { return connection; },
      quarantine(reason) { events.push('quarantine:' + reason); },
    };
    await expect(readSignedScopedMetadata(pool, signer, {
      scope, collection: 'projects', timeoutMs: 30, cleanupTimeoutMs: 30,
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(queryStarted).toBe(true);
    expect(events).toEqual(['quarantine:read-failed', 'release:true']);
  });

  test('hung ROLLBACK and release cannot hold request indefinitely', async () => {
    const h = harness();
    h.failWhen('SELECT id, ');
    const conn: ScopedSqlConnection = {
      async query(sql, params) {
        if (sql === 'ROLLBACK') return new Promise(() => {});
        if (sql === 'BEGIN') return { rows: [] };
        if (sql.includes('txid_current')) return { rows: [{ transaction_id: '123456789' }] };
        if (sql.startsWith('SELECT id, ')) throw new Error('PRIVATE SQL DETAILS');
        return { rows: [] };
      },
      release() { return new Promise(() => {}); },
    };
    const events: string[] = [];
    const pool: ScopedSqlPool = {
      async connect() { return conn; },
      quarantine(reason) { events.push(reason); },
    };
    await expect(readSignedScopedMetadata(pool, signer, {
      scope, collection: 'projects', timeoutMs: 500, cleanupTimeoutMs: 20,
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(events).toEqual(['read-failed', 'release-uncertain']);
    expect(h.releases).toEqual([]);
  });

  test('late connection after cancelled acquire gets discarded, never read', async () => {
    let resolveConnect!: (value: ScopedSqlConnection) => void;
    const incoming = new Promise<ScopedSqlConnection>((resolve) => { resolveConnect = resolve; });
    const events: string[] = [];
    const pool: ScopedSqlPool = {
      connect() { return incoming; },
      quarantine(reason) { events.push(reason); },
    };
    const pending = readSignedScopedMetadata(pool, signer, {
      scope, collection: 'projects', timeoutMs: 25, cleanupTimeoutMs: 25,
    }, () => now);
    await expect(pending).rejects.toThrow('Scoped metadata unavailable');
    resolveConnect({
      async query() { throw new Error('LATE RESERVATION MUST NOT QUERY'); },
      release(discard) { events.push('late-release:' + discard); },
    });
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(events).toContain('acquire-uncertain');
    expect(events).toContain('late-release:true');
  });

  test('successful read leaves the pool usable, failed read quarantines first', async () => {
    const h = harness();
    await readSignedScopedMetadata(h.pool, signer, {
      scope, collection: 'projects',
    }, () => now);
    expect(h.releases).toEqual([false]);
    expect(h.quarantines).toEqual([]);
    h.failWhen('SELECT id, ');
    await expect(readSignedScopedMetadata(h.pool, signer, {
      scope, collection: 'projects',
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(h.quarantines).toEqual(['read-failed']);
    expect(h.releases.at(-1)).toBe(true);
  });

  test('every resource category is a fixed, read-only SQL template', async () => {
    for (const category of [
      'tenant', 'projects', 'applications', 'client-keys',
      'accounts', 'pools', 'egress', 'routing',
    ] as const) {
      const h = harness([]);
      await readSignedScopedMetadata(h.pool, signer, {
        scope, collection: category, limit: 3,
      }, () => now);
      const select = h.calls.find((x) => x.sql.startsWith('SELECT id, '));
      expect(select?.sql).toContain('LIMIT $2');
      expect(select?.params).toEqual(['demo-north', 3]);
      expect(h.releases).toEqual([false]);
      expect(h.calls.some((x) => /\b(INSERT|UPDATE|DELETE|DROP)\b/i.test(x.sql))).toBe(false);
    }
  });
});
