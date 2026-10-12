import { beforeAll, describe, expect, test } from 'bun:test';
import {
  createPinnedHmacScopeIssuer, readSignedScopedMetadata,
  readSignedScopedAuthorizationRevision, SCOPED_AUTHORIZATION_REVISION_SQL,
  SCOPED_PUBLICATION_BARRIER_SQL, SCOPED_PUBLICATION_OUTBOX_SQL,
  withSignedScopedPublicationBarrier,
  SCOPED_READ_GATE_SQL, ScopedSqlAuthorizationDenied,
  type ScopedSqlConnection, type ScopedSqlPool, type SignedTransactionIssuer,
  type SqlRow, type SqlValue,
} from '../src/features/saasBlueprint/controlApi/server/signedSqlBoundary';
import type { AuthorizedReadScope, ControlCollection } from '../src/features/saasBlueprint/controlApi/contracts';
import {
  captureServerAuthorizationRevision,
} from '../src/features/saasBlueprint/controlApi/server/authorizationRevision';

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
], gateAnswers: readonly boolean[] = [true, true]) {
  let gateIndex = 0;
  let revisionRows: readonly SqlRow[] = [{ revision: '7', not_after_ms: null }];
  let barrierRows: readonly SqlRow[] = [{ revision: '7' }];
  let outboxRows: readonly SqlRow[] = [{ recorded: true }];
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
      if (sql === SCOPED_READ_GATE_SQL) {
        return { rows: [{ allowed: gateAnswers[gateIndex++] ?? true }] };
      }
      if (sql === SCOPED_AUTHORIZATION_REVISION_SQL) return { rows: revisionRows };
      if (sql === SCOPED_PUBLICATION_BARRIER_SQL) return { rows: barrierRows };
      if (sql === SCOPED_PUBLICATION_OUTBOX_SQL) return { rows: outboxRows };
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
    onQuery: (fn: (sql: string) => void) => { afterCall = fn; },
    setRevisionRows: (items: readonly SqlRow[]) => { revisionRows = items; },
    setBarrierRows: (items: readonly SqlRow[]) => { barrierRows = items; },
    setOutboxRows: (items: readonly SqlRow[]) => { outboxRows = items; } };
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
        if (sql === SCOPED_READ_GATE_SQL) return { rows: [{ allowed: true }] };
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
      async query(sql) {
        if (sql === 'ROLLBACK') return new Promise(() => {});
        if (sql === 'BEGIN') return { rows: [] };
        if (sql.includes('txid_current')) return { rows: [{ transaction_id: '123456789' }] };
        if (sql === SCOPED_READ_GATE_SQL) return { rows: [{ allowed: true }] };
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

  test('missing active tenant or DB membership denies BEFORE SELECT with clean ROLLBACK', async () => {
    const h = harness(undefined, [false]);
    await expect(readSignedScopedMetadata(h.pool, signer, {
      scope, collection: 'projects',
    }, () => now)).rejects.toBeInstanceOf(ScopedSqlAuthorizationDenied);
    expect(h.calls.filter(x => x.sql === SCOPED_READ_GATE_SQL)).toHaveLength(1);
    expect(h.calls.find(x => x.sql.startsWith('SELECT id, '))).toBeUndefined();
    expect(h.calls.at(-1)?.sql).toBe('ROLLBACK');
    expect(h.releases).toEqual([false]);
    expect(h.quarantines).toEqual([]);
    // A confirmed, successful rollback does not poison a healthy pool.
    const rows = await readSignedScopedMetadata(h.pool, signer, {
      scope, collection: 'projects',
    }, () => now);
    expect(rows.map(row => row.id)).toEqual(['project-north']);
    expect(h.releases).toEqual([false, false]);
  });

  test('revocation AFTER SELECT fails post-read SQL gate and never commits rows', async () => {
    const h = harness(undefined, [true, false]);
    await expect(readSignedScopedMetadata(h.pool, signer, {
      scope, collection: 'projects',
    }, () => now)).rejects.toBeInstanceOf(ScopedSqlAuthorizationDenied);
    expect(h.calls.some(x => x.sql.startsWith('SELECT id, '))).toBe(true);
    expect(h.calls.filter(x => x.sql === SCOPED_READ_GATE_SQL)).toHaveLength(2);
    expect(h.calls.some(x => x.sql === 'COMMIT')).toBe(false);
    expect(h.calls.at(-1)?.sql).toBe('ROLLBACK');
    expect(h.quarantines).toEqual([]);
    expect(h.releases).toEqual([false]);
  });

  test('malformed SQL authorization result quarantines rather than granting access', async () => {
    const events: string[] = [];
    const conn: ScopedSqlConnection = {
      async query(sql) {
        if (sql.includes('txid_current')) return { rows: [{ transaction_id: '123456789' }] };
        if (sql === SCOPED_READ_GATE_SQL) return { rows: [{ allowed: 'true' }] };
        return { rows: [] };
      },
      release(discard) { events.push('release:' + discard); },
    };
    const pool: ScopedSqlPool = {
      async connect() { return conn; },
      quarantine(reason) { events.push('quarantine:' + reason); },
    };
    await expect(readSignedScopedMetadata(pool, signer, {
      scope, collection: 'projects',
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(events).toEqual(['quarantine:read-failed', 'release:true']);
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

describe('Stage 2G.4d.3 — signed PostgreSQL revision attestation (fake pool)', () => {
  test('uses fixed SQL, exact actor/tenant/role/collection and dual DB gates', async () => {
    const h = harness();
    const revision = await readSignedScopedAuthorizationRevision(h.pool, signer, {
      scope, collection: 'projects',
    }, () => now);
    expect(revision).toEqual({ revision: '7', notAfterMs: null });
    expect(h.calls.filter(x => x.sql === SCOPED_AUTHORIZATION_REVISION_SQL))
      .toEqual([{ sql: SCOPED_AUTHORIZATION_REVISION_SQL,
        params: ['demo-north', 'actor-north', 'tenant-admin', 'projects'] }]);
    expect(h.calls.filter(x => x.sql === SCOPED_READ_GATE_SQL)).toHaveLength(2);
    expect(h.calls.filter(x => x.sql.startsWith('SELECT set_config'))).toHaveLength(5);
    expect(h.calls.some(x => x.sql.startsWith('SELECT id, '))).toBe(false);
    expect(h.calls.at(-1)?.sql).toBe('COMMIT');
    expect(h.releases).toEqual([false]);
    expect(h.quarantines).toEqual([]);
    expect(h.calls.map(x => x.sql).join(' ')).not.toContain('actor-north');
  });

  test('database gate denies before or after revision SELECT with safe ROLLBACK', async () => {
    for (const answers of [[false], [true, false]]) {
      const h = harness(undefined, answers);
      await expect(readSignedScopedAuthorizationRevision(h.pool, signer, {
        scope, collection: 'projects',
      }, () => now)).rejects.toBeInstanceOf(ScopedSqlAuthorizationDenied);
      expect(h.calls.at(-1)?.sql).toBe('ROLLBACK');
      expect(h.releases).toEqual([false]);
      expect(h.quarantines).toEqual([]);
      expect(h.calls.filter(x => x.sql === SCOPED_AUTHORIZATION_REVISION_SQL))
        .toHaveLength(answers[0] ? 1 : 0);
    }
  });

  test('signed SQL NULL is a generic denial, not a revision zero or Allow', async () => {
    const h = harness();
    h.setRevisionRows([{ revision: null, not_after_ms: null }]);
    await expect(readSignedScopedAuthorizationRevision(h.pool, signer, {
      scope, collection: 'projects',
    }, () => now)).rejects.toBeInstanceOf(ScopedSqlAuthorizationDenied);
    expect(h.releases).toEqual([false]);
    expect(h.calls.at(-1)?.sql).toBe('ROLLBACK');
  });

  test('missing, overflow, duplicate, numeric and malformed attestation quarantines', async () => {
    for (const rows of [
      [], [{ revision: 7 }], [{ revision: undefined }],
      [{ revision: '07' }], [{ revision: '0' }],
      [{ revision: '9223372036854775808' }],
      [{ revision: '7' }, { revision: '8' }],
      [{ revision: '7; DROP TABLE sensitive' }],
      [{ revision: '7', not_after_ms: undefined }],
      [{ revision: '7', not_after_ms: 42 }],
      [{ revision: '7', not_after_ms: '07' }],
      [{ revision: '7', not_after_ms: '9007199254740993' }],
      [{ revision: '7', not_after_ms: '-1' }],
    ]) {
      const h = harness();
      h.setRevisionRows(rows);
      await expect(readSignedScopedAuthorizationRevision(h.pool, signer, {
        scope, collection: 'projects',
      }, () => now)).rejects.toThrow('Scoped metadata unavailable');
      expect(h.quarantines).toContain('read-failed');
      expect(h.releases).toEqual([true]);
      expect(h.calls.some(x => x.sql === 'COMMIT')).toBe(false);
    }
  });

  test('revision driver failure never exposes SQL details and quarantines', async () => {
    const h = harness();
    h.failWhen('authorized_revision');
    await expect(readSignedScopedAuthorizationRevision(h.pool, signer, {
      scope, collection: 'projects',
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(h.quarantines).toEqual(['read-failed']);
    expect(h.releases).toEqual([true]);
  });

  test('cancel during revision SQL fails closed, discards and never commits', async () => {
    const h = harness();
    const controller = new AbortController();
    h.onQuery(sql => {
      if (sql === SCOPED_AUTHORIZATION_REVISION_SQL) controller.abort();
    });
    await expect(readSignedScopedAuthorizationRevision(h.pool, signer, {
      scope, collection: 'projects', signal: controller.signal,
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(h.calls.some(x => x.sql === 'COMMIT')).toBe(false);
    expect(h.quarantines).toContain('read-failed');
    expect(h.releases).toEqual([true]);
  });

  test('revision read rejects foreign scope and untrusted collection pre-connection', async () => {
    const h = harness();
    await expect(readSignedScopedAuthorizationRevision(h.pool, signer, {
      scope: { ...scope, tenantId: 'north;DROP' }, collection: 'projects',
    }, () => now)).rejects.toThrow();
    await expect(readSignedScopedAuthorizationRevision(h.pool, signer, {
      scope, collection: '__proto__' as ControlCollection,
    }, () => now)).rejects.toThrow();
    expect(h.calls).toEqual([]);
  });
});

describe('Stage 2G.4d.4b — signed next-grant-expiry clock guard', () => {
  test('accepts a canonical server-only deadline without displaying it', async () => {
    const h = harness();
    h.setRevisionRows([{ revision: '42', not_after_ms: '1890000000000' }]);
    const attestation = await readSignedScopedAuthorizationRevision(h.pool, signer, {
      scope, collection: 'accounts',
    }, () => now);
    expect(attestation).toEqual({ revision: '42', notAfterMs: '1890000000000' });
    expect(h.calls.find(x => x.sql === SCOPED_AUTHORIZATION_REVISION_SQL)?.params)
      .toEqual(['demo-north', 'actor-north', 'tenant-admin', 'accounts']);
    expect(h.quarantines).toEqual([]);
    expect(h.releases).toEqual([false]);
  });

  test('missing expiry column is a malformed DB result, not an Allow', async () => {
    const h = harness();
    h.setRevisionRows([{ revision: '42' }]);
    await expect(readSignedScopedAuthorizationRevision(h.pool, signer, {
      scope, collection: 'projects',
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(h.quarantines).toEqual(['read-failed']);
    expect(h.releases).toEqual([true]);
  });
});

/** Branded baseline can be captured ONLY after a trusted scope is derived. */
async function pubBaseline(revision = '7', until: string | null = null) {
  return captureServerAuthorizationRevision({
    async readRevision() { return { revision, notAfterMs: until }; },
  }, scope, 'projects', new AbortController().signal);
}

describe('Stage 2G.4d.5a — bounded signed publication (synthetic local handoff)', () => {
  test('holds signed FOR SHARE throughout private prepare and synchronous handoff', async () => {
    const h = harness();
    const baseline = await pubBaseline();
    const events: string[] = [];
    h.onQuery(sql => { if (sql === 'COMMIT') events.push('sql:COMMIT'); });
    await withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline, timeoutMs: 500,
      handoff: {
        async prepare(signal) {
          expect(signal.aborted).toBe(false);
          expect(h.calls.filter(q => q.sql === SCOPED_PUBLICATION_BARRIER_SQL))
            .toHaveLength(1);
          events.push('stage:private');
          await Promise.resolve();
          return () => { events.push('handoff:local'); };
        },
      },
    }, () => now);
    expect(events).toEqual(['stage:private', 'handoff:local', 'sql:COMMIT']);
    expect(h.calls.filter(q => q.sql === SCOPED_PUBLICATION_BARRIER_SQL))
      .toEqual([{ sql: SCOPED_PUBLICATION_BARRIER_SQL,
        params: ['demo-north', 'actor-north', 'tenant-admin', 'projects'] }]);
    expect(h.calls.filter(q => q.sql === SCOPED_READ_GATE_SQL)).toHaveLength(2);
    expect(h.calls.filter(q => q.sql.startsWith('SELECT set_config'))).toHaveLength(5);
    expect(h.calls.filter(q => q.sql === SCOPED_AUTHORIZATION_REVISION_SQL))
      .toHaveLength(1);
    expect(h.calls.filter(q => q.sql.startsWith('SELECT id, '))).toHaveLength(0);
    expect(h.releases).toEqual([false]);
    expect(h.quarantines).toEqual([]);
  });

  test('revision drift after metadata read is 404 before preparing any bytes', async () => {
    const h = harness();
    const baseline = await pubBaseline('8');
    let prepared = false;
    await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline,
      handoff: { async prepare() { prepared = true; return () => {}; } },
    }, () => now)).rejects.toBeInstanceOf(ScopedSqlAuthorizationDenied);
    expect(prepared).toBe(false);
    expect(h.calls.at(-1)?.sql).toBe('ROLLBACK');
    expect(h.releases).toEqual([false]);
    expect(h.quarantines).toEqual([]);
  });

  test('DB NULL/foreign signed barrier is 404, not a staging callback', async () => {
    const h = harness();
    h.setBarrierRows([{ revision: null }]);
    const baseline = await pubBaseline();
    await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline,
      handoff: { async prepare() { throw new Error('MUST_NOT_PREPARE'); } },
    }, () => now)).rejects.toBeInstanceOf(ScopedSqlAuthorizationDenied);
    expect(h.calls.at(-1)?.sql).toBe('ROLLBACK');
    expect(h.releases).toEqual([false]);
  });

  test('same epoch with changed grant deadline is a safe 404, no handoff', async () => {
    const h = harness();
    h.setRevisionRows([{ revision: '7', not_after_ms: null }]);
    const baseline = await pubBaseline('7', String(Date.now() + 60_000));
    await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline,
      handoff: { async prepare() { throw new Error('MUST_NOT_PREPARE'); } },
    }, () => now)).rejects.toBeInstanceOf(ScopedSqlAuthorizationDenied);
    expect(h.quarantines).toEqual([]);
    expect(h.releases).toEqual([false]);
  });

  test('malformed signed lock/expiry SQL result quarantines physical reservation', async () => {
    const baseline = await pubBaseline();
    for (const malformedLock of [[], [{ revision: 7 }], [{ revision: '07' }],
      [{ revision: '7' }, { revision: '7' }]]) {
      const h = harness();
      h.setBarrierRows(malformedLock);
      await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
        scope, collection: 'projects', baseline,
        handoff: { async prepare() { throw new Error('NEVER'); } },
      }, () => now)).rejects.toThrow('Scoped metadata unavailable');
      expect(h.quarantines).toEqual(['read-failed']);
      expect(h.releases).toEqual([true]);
    }
    const h = harness();
    h.setRevisionRows([{ revision: '7', not_after_ms: undefined }]);
    await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline,
      handoff: { async prepare() { throw new Error('NEVER'); } },
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(h.quarantines).toEqual(['read-failed']);
    expect(h.releases).toEqual([true]);
  });

  test('DB gate changed after staging denies without executing local handoff', async () => {
    const h = harness(undefined, [true, false]);
    const baseline = await pubBaseline();
    let committed = false;
    await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline,
      handoff: { async prepare() { return () => { committed = true; }; } },
    }, () => now)).rejects.toBeInstanceOf(ScopedSqlAuthorizationDenied);
    expect(committed).toBe(false);
    expect(h.calls.at(-1)?.sql).toBe('ROLLBACK');
    expect(h.releases).toEqual([false]);
  });

  test('cancellation during prepare fails closed and never invokes a late commit', async () => {
    const controller = new AbortController();
    const h = harness();
    const baseline = await pubBaseline();
    let commitCalls = 0;
    let resolvePrepare!: (fn: () => void) => void;
    const wait = new Promise<() => void>(r => { resolvePrepare = r; });
    let started!: () => void;
    const staged = new Promise<void>(r => { started = r; });
    const pending = withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline, signal: controller.signal,
      handoff: { prepare() { started(); return wait; } },
    }, () => now);
    await staged;
    controller.abort();
    await expect(pending).rejects.toThrow('Scoped metadata unavailable');
    resolvePrepare(() => { commitCalls++; });
    await Promise.resolve();
    expect(commitCalls).toBe(0);
    expect(h.quarantines).toEqual(['read-failed']);
    expect(h.releases).toEqual([true]);
    expect(h.calls.some(q => q.sql === 'COMMIT')).toBe(false);
  });

  test('hung private prepare is bounded even when it ignores its AbortSignal', async () => {
    const h = harness();
    const baseline = await pubBaseline();
    await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline, timeoutMs: 30, cleanupTimeoutMs: 30,
      handoff: { async prepare() { return new Promise(() => {}); } },
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(h.calls.some(q => q.sql === 'COMMIT')).toBe(false);
    expect(h.quarantines).toEqual(['read-failed']);
    expect(h.releases).toEqual([true]);
  });

  test('client-like forged baseline/collection denied BEFORE SQL connection', async () => {
    const h = harness();
    const baseline = await pubBaseline();
    for (const request of [
      { scope, collection: '__proto__' as ControlCollection, baseline },
      { scope: { ...scope, tenantId: 'demo-orbit;--' }, collection: 'projects' as const, baseline },
      { scope, collection: 'projects' as const, baseline: { value: '07', notAfterMs: null } },
    ]) {
      await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
        ...request, handoff: { async prepare() { return () => {}; } },
      } as Parameters<typeof withSignedScopedPublicationBarrier>[2], () => now))
        .rejects.toThrow();
    }
    expect(h.calls).toEqual([]);
  });

  test('invalid prepare result or rejected local handoff cannot be Allow', async () => {
    const baseline = await pubBaseline();
    for (const behavior of [
      async () => 1,
      async () => { throw new Error('PRIVATE_STAGED_BYTES'); },
    ]) {
      const h = harness();
      await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
        scope, collection: 'projects', baseline,
        handoff: { prepare: behavior as never },
      }, () => now)).rejects.toThrow('Scoped metadata unavailable');
      expect(h.calls.some(q => q.sql === 'COMMIT')).toBe(false);
      expect(h.quarantines).toEqual(['read-failed']);
    }
  });
});

describe('Stage 2G.4d.6b — signed durable-on-COMMIT audit pilot (fake SQL)', () => {
  test('fixed parameterized append happens AFTER DB gates, BEFORE local handoff', async () => {
    const h = harness();
    const baseline = await pubBaseline();
    const events: string[] = [];
    h.onQuery(sql => {
      if (sql === SCOPED_PUBLICATION_OUTBOX_SQL) events.push('sql:audit-pending');
      if (sql === 'COMMIT') events.push('sql:COMMIT');
    });
    await withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline, recordStagingOutbox: true,
      handoff: { async prepare() {
        events.push('private:stage');
        return () => { events.push('local:handoff'); };
      } },
    }, () => now);
    expect(events).toEqual([
      'private:stage', 'sql:audit-pending', 'local:handoff', 'sql:COMMIT',
    ]);
    expect(h.calls.filter(x => x.sql === SCOPED_PUBLICATION_OUTBOX_SQL))
      .toEqual([{ sql: SCOPED_PUBLICATION_OUTBOX_SQL,
        params: ['demo-north','actor-north','tenant-admin','projects','server-trace'] }]);
    expect(h.quarantines).toEqual([]);
    expect(h.releases).toEqual([false]);
  });

  test('revoked DB actor/outbox denial rolls back WITHOUT handoff or Allow', async () => {
    const h = harness();
    h.setOutboxRows([{ recorded: false }]);
    const baseline = await pubBaseline();
    let published = false;
    await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline, recordStagingOutbox: true,
      handoff: { async prepare() { return () => { published = true; }; } },
    }, () => now)).rejects.toBeInstanceOf(ScopedSqlAuthorizationDenied);
    expect(published).toBe(false);
    expect(h.calls.at(-1)?.sql).toBe('ROLLBACK');
    expect(h.releases).toEqual([false]);
    expect(h.quarantines).toEqual([]);
  });

  test('malformed or failed signed audit write quarantines and never emits', async () => {
    for (const malformed of [[], [{ recorded: 'true' }],
      [{ recorded: true }, { recorded: false }], [{ no_record: true }]]) {
      const h = harness();
      h.setOutboxRows(malformed);
      let published = false;
      await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
        scope, collection: 'projects', baseline: await pubBaseline(),
        recordStagingOutbox: true,
        handoff: { async prepare() { return () => { published = true; }; } },
      }, () => now)).rejects.toThrow('Scoped metadata unavailable');
      expect(published).toBe(false);
      expect(h.quarantines).toEqual(['read-failed']);
      expect(h.releases).toEqual([true]);
    }
    const h = harness();
    h.failWhen('record_signed_local_publication');
    await expect(withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline: await pubBaseline(),
      recordStagingOutbox: true,
      handoff: { async prepare() { return () => {}; } },
    }, () => now)).rejects.toThrow('Scoped metadata unavailable');
    expect(h.quarantines).toEqual(['read-failed']);
    expect(h.releases).toEqual([true]);
  });

  test('outbox is opt-in: old isolated publication never calls migration 009', async () => {
    const h = harness();
    await withSignedScopedPublicationBarrier(h.pool, signer, {
      scope, collection: 'projects', baseline: await pubBaseline(),
      handoff: { async prepare() { return () => {}; } },
    }, () => now);
    expect(h.calls.some(x => x.sql === SCOPED_PUBLICATION_OUTBOX_SQL)).toBe(false);
  });
});
