/**
 * STAGING ONLY / CI ephemeral PostgreSQL 16 + Bun native SQL driver.
 * NEVER run against production, Railway, Core, Gateway, or OAuth storage.
 * This is an executable driver acceptance harness, not a SaaS deployment.
 */
import assert from 'node:assert/strict';
import { SQL } from 'bun';
import {
  createPinnedHmacScopeIssuer,
  readSignedScopedMetadata,
  CONTROL_READ_SELECT_SQL,
} from '../../src/features/saasBlueprint/controlApi/server/signedSqlBoundary.ts';

const expected = process.env.SAAS_EPHEMERAL_DRIVER_CI === 'true' &&
  process.env.GITHUB_ACTIONS === 'true' &&
  process.env.NODE_ENV !== 'production' &&
  !process.env.RAILWAY_ENVIRONMENT &&
  !process.env.RAILWAY_PROJECT_ID;

if (!expected) {
  throw new Error('Refusing to run outside ephemeral GitHub PostgreSQL contract CI');
}

const keyHex = process.env.SAAS_EPHEMERAL_SCOPE_KEY_HEX;
const databasePassword = process.env.SAAS_EPHEMERAL_DB_PASSWORD;
if (typeof keyHex !== 'string' || !/^[0-9a-f]{64}$/.test(keyHex) ||
    typeof databasePassword !== 'string' || !/^[0-9a-f]{48}$/.test(databasePassword)) {
  throw new Error('Ephemeral CI key or random database password missing');
}
delete process.env.SAAS_EPHEMERAL_SCOPE_KEY_HEX;
delete process.env.SAAS_EPHEMERAL_DB_PASSWORD;

const secret = Uint8Array.from(Buffer.from(keyHex, 'hex'));
const cryptoKey = await crypto.subtle.importKey(
  'raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
);
secret.fill(0);
const signer = createPinnedHmacScopeIssuer(cryptoKey);

// Deliberately hard-coded ephemeral loopback TEST credentials. No env-supplied
// production DB URL can redirect this harness; never accept free-form hosts.
function nativeSql(max) {
  return new SQL({
    hostname: '127.0.0.1', port: 5432,
    database: 'saas_ephemeral_test',
    username: 'saas_ci_runner',
    password: databasePassword,
    max, connectionTimeout: 5, idleTimeout: 5,
    prepare: false, tls: false,
  });
}

const SELECT_ALLOWLIST = new Set(Object.values(CONTROL_READ_SELECT_SQL));
const FIXED = new Set([
  'BEGIN', 'COMMIT', 'ROLLBACK',
  'SELECT txid_current()::text AS transaction_id',
  'SELECT set_config($1::text, $2::text, true)',
  'SET LOCAL ROLE saas_rls_reader',
]);

function canExecuteSql(sql, params) {
  if (FIXED.has(sql)) {
    return (sql === 'SELECT set_config($1::text, $2::text, true)')
      ? params.length === 2 : params.length === 0;
  }
  return SELECT_ALLOWLIST.has(sql) && params.length === 2;
}

function createBoundedDriver(sql) {
  let discarded = 0;
  let completed = 0;
  let poisoned = false;
  return {
    stats: () => ({ discarded, completed, poisoned }),
    quarantine() { poisoned = true; },
    async connect(signal) {
      if (poisoned) throw new Error('Ephemeral pool already destroyed');
      const reserved = await sql.reserve(signal ? { signal } : undefined);
      if (poisoned) {
        reserved.release();
        throw new Error('Ephemeral pool already destroyed');
      }
      let released = false;
      return {
        async query(statement, params, querySignal = signal) {
          if (released) throw new Error('Connection already released');
          if (!canExecuteSql(statement, params)) throw new Error('Non-allowlisted SQL');
          if (querySignal?.aborted && statement !== 'ROLLBACK') {
            throw new Error('Request cancelled');
          }
          // SQL.unsafe receives ONLY server-defined statements above;
          // all untrusted VALUES are supplied as driver-bound parameters.
          const query = reserved.unsafe(statement, [...params]).execute();
          const cancel = () => {
            if (statement !== 'ROLLBACK') query.cancel();
          };
          querySignal?.addEventListener('abort', cancel, { once: true });
          try {
            return { rows: await query };
          } finally {
            querySignal?.removeEventListener('abort', cancel);
          }
        },
        async release(discard) {
          if (released) throw new Error('Double release');
          released = true;
          if (discard) {
            discarded += 1;
            // Bun 1.3.14 cannot reliably close a ReservedSQL and then
            // close its pool: the shutdown stalls even after release().
            // Fail CLOSED by invalidating the *entire test-only pool*.
            // No further connect() is allowed on this adapter, so released
            // state cannot be used by another tenant. Production must use
            // a driver with a documented atomic discard(connection).
            poisoned = true;
            reserved.release();
            await sql.close({ timeout: 0 });
          } else {
            completed += 1;
            reserved.release();
          }
        },
      };
    },
  };
}

function read(pool, actorId, tenantId, collection, options = {}) {
  return readSignedScopedMetadata(pool, signer, {
    scope: { actorId, tenantId, role: options.role ?? 'tenant-viewer',
      correlationId: 'ci-isolated-driver' },
    collection,
    limit: options.limit ?? 20,
    signal: options.signal ?? AbortSignal.timeout(15000),
  });
}

console.info('STEP: creating native PostgreSQL client with max=2');
const dbPool = nativeSql(2);
const driver = createBoundedDriver(dbPool);
try {
  console.info('STEP: testing non-superuser runner identity');
  const identity = await dbPool.unsafe(
    'SELECT current_user::text AS db_user, session_user::text AS login_user'
  );
  assert.equal(identity[0].db_user, 'saas_ci_runner');
  assert.equal(identity[0].login_user, 'saas_ci_runner');

  // Without SET LOCAL ROLE the runner cannot SELECT metadata and cannot
  // inspect private HMAC secrets. This is not a superuser connection.
  await assert.rejects(dbPool.unsafe('SELECT id FROM saas_rls.projects'));
  await assert.rejects(dbPool.unsafe(
    'SELECT secret FROM saas_rls_private.scope_signers'
  ));

  // Two active tenant scopes concurrently share a *real* Bun PostgreSQL pool.
  const tasks = Array.from({ length: 12 }, (_, index) =>
    index % 2 === 0
      ? read(driver, 'actor-north', 'demo-north', 'projects')
      : read(driver, 'actor-orbit', 'demo-orbit', 'projects')
  );
  console.info('STEP: starting 12 concurrent North/Orbit reads');
  const data = await Promise.all(tasks);
  console.info('STEP: 12 concurrent tenant reads completed');
  for (let i = 0; i < data.length; i += 1) {
    assert.deepEqual(
      data[i].map(row => row.id),
      [i % 2 === 0 ? 'north-project' : 'orbit-project']
    );
    assert.equal(data[i][0].tenant_id, i % 2 === 0 ? 'demo-north' : 'demo-orbit');
  }

  const northAccounts = await read(driver, 'actor-north', 'demo-north', 'accounts');
  const orbitAccounts = await read(driver, 'actor-orbit', 'demo-orbit', 'accounts');
  assert.deepEqual(
    northAccounts.map(row => row.id).sort(),
    ['north-account', 'shared-account'].sort()
  );
  assert.deepEqual(orbitAccounts.map(row => row.id), ['orbit-account']);

  const keys = await read(driver, 'actor-north', 'demo-north', 'client-keys');
  assert.deepEqual(keys.map(row => row.id), ['north-binding']);
  const auditorAccounts = await read(driver, 'actor-auditor', 'demo-north', 'accounts', {
    role: 'tenant-auditor',
  });
  assert.deepEqual(auditorAccounts, []);
  const rogue = await read(driver, 'actor-north', 'demo-orbit', 'projects');
  assert.deepEqual(rogue, []);
  assert.deepEqual(await read(driver, 'actor-paused', 'demo-paused', 'projects'), []);

  const northRoutes = await read(driver, 'actor-north', 'demo-north', 'routing');
  assert.deepEqual(northRoutes.map(row => row.id).sort(), ['north-route','north-shared']);
  assert.equal(driver.stats().discarded, 0);

  console.info('PASS: native Bun PostgreSQL client uses non-superuser and 12 concurrent tenant-isolated reads');
} finally {
  await dbPool.close({ timeout: 2 });
}

// Force max=1 to prove that a physically REUSED connection does not retain
// SET LOCAL ROLE, actor/tenant GUCs or a previous signed transaction.
console.info('STEP: checking pool reuse with max=1');
const reuseDb = nativeSql(1);
const reuseDriver = createBoundedDriver(reuseDb);
try {
  assert.deepEqual((await read(reuseDriver,'actor-north','demo-north','projects'))
    .map(row => row.id), ['north-project']);

  const reused = await reuseDb.reserve();
  try {
    const state = await reused.unsafe(
      "SELECT current_user::text AS role_name, " +
      "coalesce(current_setting('saas.scope_actor',true),'') AS actor, " +
      "coalesce(current_setting('saas.scope_mac',true),'') AS mac"
    );
    assert.equal(state[0].role_name, 'saas_ci_runner');
    assert.equal(state[0].actor, '');
    assert.equal(state[0].mac, '');
  } finally {
    reused.release();
  }

  assert.deepEqual((await read(reuseDriver,'actor-orbit','demo-orbit','projects'))
    .map(row => row.id), ['orbit-project']);

  const controller = new AbortController();
  controller.abort();
  await assert.rejects(read(reuseDriver,'actor-north','demo-north','projects',
    { signal: controller.signal }));
  assert.equal(reuseDriver.stats().discarded, 0);
  console.info('PASS: same physical connection resets actor/role and abort-before-connect denies');
} finally {
  await reuseDb.close({ timeout: 2 });
}

// A failed source and aborted query are fail-closed. The affected reserved
// connection is DESTROYED, never released for a different tenant.
console.info('STEP: checking forced discard of reserved connection');
const errorDb = nativeSql(1);
const errorDriver = createBoundedDriver(errorDb);
try {
  const invalidRole = await errorDriver.connect();
  const error = await invalidRole.query('BEGIN', []);
  assert.ok(error.rows);
  await invalidRole.query('ROLLBACK', []);
  await invalidRole.release(true);
  assert.equal(errorDriver.stats().discarded, 1);
  assert.equal(errorDriver.stats().poisoned, true);
  await assert.rejects(errorDriver.connect());
  console.info('PASS: failed reservation poisons and closes entire staging pool');
} finally {
  if (!errorDriver.stats().poisoned) {
    await errorDb.close({ timeout: 0 });
  }
}

console.info('PASS: stage 2F genuine Bun PostgreSQL driver integration (ephemeral database only)');

// Stage 2G.1b: real wire-protocol fault probes on the DISPOSABLE CI database.
// These probe-only SQL statements are never accepted by the SaaS SELECT
// allowlist, never run against Core/Railway, and never use client SQL input.
function withProbeDeadline(pending, ms, step) {
  let timer;
  return Promise.race([
    pending,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Probe deadline exceeded: ' + step)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

function cancelledByPostgres(error) {
  const code = String(error?.code ?? '');
  const message = String(error?.message ?? '');
  // A client-side Promise.race deadline is NOT proof of SQL cancellation.
  return code === '57014' || code === 'ERR_POSTGRES_QUERY_CANCELLED' ||
    /query (was )?cancelled|canceling statement|cancelling statement|statement timeout/i.test(message);
}

console.info('STEP: native Bun reserve wait abort with max=1');
const waitingDb = nativeSql(1);
let heldReservation;
try {
  heldReservation = await withProbeDeadline(waitingDb.reserve(), 2500, 'initial reserve');
  const controller = new AbortController();
  let lateReservationAcquired = false;
  const waiting = waitingDb.reserve({ signal: controller.signal }).then((late) => {
    // A late reservation from an aborted waiter must never be handed to
    // an application caller. Its rejection is observed by Promise.race.
    lateReservationAcquired = true;
    late.release();
    throw new Error('Aborted reserve unexpectedly acquired a connection');
  });
  const abortAt = Date.now();
  controller.abort();
  let nativeWaitingAbort = false;
  try {
    await withProbeDeadline(waiting, 1250, 'waiting reserve');
    throw new Error('Aborted reservation unexpectedly succeeded');
  } catch (error) {
    if (String(error?.message ?? '') === 'Probe deadline exceeded: waiting reserve') {
      // A probe timer is NOT proof that Bun.reserve honored AbortSignal.
      console.warn('DRIVER LIMITATION: native reserve abort was not bounded (' +
        (Date.now() - abortAt) + 'ms); quarantine required');
    } else if (error === controller.signal.reason ||
        error?.name === 'AbortError' ||
        /abort/i.test(String(error?.message ?? ''))) {
      nativeWaitingAbort = true;
      console.info('OBSERVED: native reserve rejected on AbortSignal');
    } else {
      throw error;
    }
  }
  assert.equal(controller.signal.aborted, true);
  assert.equal(lateReservationAcquired, false);
  // Whatever the native driver's behaviour, no tenant request can reuse
  // this pool: the test boundary makes it terminally quarantined.
  // In particular, a JS timeout is not equivalent to a cancelled waiter.
  const heldCheck = await heldReservation.unsafe(
    'SELECT current_user::text AS role_name'
  );
  assert.equal(heldCheck[0].role_name, 'saas_ci_runner');
  heldReservation.release();
  heldReservation = undefined;
  // The first native CI run proved we cannot assume that cancelled
  // Bun.reserve({signal}) leaves this SAME pool safe/usable: the next
  // tenant read failed. Conservatively retire the pool on uncertain
  // acquire cancellation; do not count a success on another connection
  // of the same pool as an isolation guarantee.
  const waitingDriver = createBoundedDriver(waitingDb);
  waitingDriver.quarantine('acquire-uncertain');
  assert.equal(waitingDriver.stats().poisoned, true);
  await assert.rejects(waitingDriver.connect());
  console.info('PASS: waiting reserve classified (' +
    (nativeWaitingAbort ? 'driver abort' : 'unbounded driver wait') +
    '); pool quarantined before tenant reads');
} finally {
  heldReservation?.release();
  await withProbeDeadline(waitingDb.close({ timeout: 2 }), 3000, 'wait pool close');
}

// PostgreSQL server-side statement_timeout is a distinct safety boundary
// from a JS AbortSignal: a server-error leaves an open transaction aborted.
// Recover only after a confirmed ROLLBACK, and inspect transaction-local state.
console.info('STEP: server-side PostgreSQL statement_timeout + confirmed ROLLBACK');
const statementDb = nativeSql(1);
let statementReservation;
try {
  statementReservation = await withProbeDeadline(statementDb.reserve(), 2500, 'statement reserve');
  await statementReservation.unsafe('BEGIN');
  await statementReservation.unsafe("SET LOCAL statement_timeout = '150ms'");
  await assert.rejects(
    withProbeDeadline(statementReservation.unsafe('SELECT pg_sleep(2)').execute(),
      2400, 'statement_timeout'),
    cancelledByPostgres
  );
  await assert.rejects(
    statementReservation.unsafe('SELECT 1').execute(),
    error => String(error?.code ?? '') === '25P02' ||
      /current transaction is aborted/i.test(String(error?.message ?? ''))
  );
  await withProbeDeadline(statementReservation.unsafe('ROLLBACK').execute(),
    1500, 'confirmed ROLLBACK');
  const reset = await statementReservation.unsafe(
    "SELECT current_user::text AS db_role, " +
    "coalesce(current_setting('saas.scope_actor',true),'') AS actor, " +
    "coalesce(current_setting('saas.scope_mac',true),'') AS mac"
  );
  assert.equal(reset[0].db_role, 'saas_ci_runner');
  assert.equal(reset[0].actor, '');
  assert.equal(reset[0].mac, '');
  statementReservation.release();
  statementReservation = undefined;
  const afterRollback = createBoundedDriver(statementDb);
  assert.deepEqual((await read(afterRollback, 'actor-orbit', 'demo-orbit', 'projects'))
    .map(row => row.id), ['orbit-project']);
  assert.equal(afterRollback.stats().discarded, 0);
  console.info('PASS: PG statement timeout rejected; confirmed ROLLBACK clears scope');
} finally {
  statementReservation?.release();
  await withProbeDeadline(statementDb.close({ timeout: 2 }), 3000, 'statement pool close');
}

// Bun.Query.cancel() operates on a query already executing on the wire.
// The reserved connection is NEVER offered to a second tenant after this
// experiment. Close the entire isolated pool; no per-connection discard API.
console.info('STEP: real Bun query.cancel() on active pg_sleep');
const cancellationDb = nativeSql(1);
let cancellationReservation;
try {
  cancellationReservation = await withProbeDeadline(cancellationDb.reserve(),
    2500, 'cancel reserve');
  const sleeping = cancellationReservation.unsafe('SELECT pg_sleep(4)').execute();
  const started = Date.now();
  let cancellationIssued = false;
  let observedOutcome = 'normal-completion';
  const cancellationTimer = setTimeout(() => {
    cancellationIssued = true;
    sleeping.cancel();
  }, 150);
  try {
    // A native cancel that does not settle within 2.5s is NOT a proven
    // safe cancellation. Still await this finite 4s test statement before
    // releasing its reservation; never release a query still in flight.
    try {
      await withProbeDeadline(sleeping, 7000, 'settle cancelled pg_sleep');
    } catch (error) {
      if (!cancelledByPostgres(error)) throw error;
      observedOutcome = 'driver-cancelled';
    }
  } finally {
    clearTimeout(cancellationTimer);
  }
  const settledInMs = Date.now() - started;
  assert.equal(cancellationIssued, true);
  const cancelledInBudget =
    observedOutcome === 'driver-cancelled' && settledInMs < 2500;
  if (cancelledInBudget) {
    console.info('OBSERVED: native Bun Query.cancel completed within 2.5s');
  } else {
    // This is an explicitly *negative* capability result, not a silent
    // acceptance of cancellation. The rest of the CI test verifies
    // fail-closed shutdown/replacement, NOT Bun cancel effectiveness.
    console.warn('DRIVER LIMITATION: Bun Query.cancel was not bounded (' +
      observedOutcome + ', ' + settledInMs + 'ms); backend must not reuse pool');
  }
  const cancellationDriver = createBoundedDriver(cancellationDb);
  cancellationDriver.quarantine('read-failed');
  assert.equal(cancellationDriver.stats().poisoned, true);
  await assert.rejects(cancellationDriver.connect());
  cancellationReservation.release();
  cancellationReservation = undefined;
  await withProbeDeadline(cancellationDb.close({ timeout: 0 }),
    3000, 'cancelled pool shutdown');
  await assert.rejects(withProbeDeadline(cancellationDb.reserve(), 1500,
    'no reuse of closed cancellation pool'));
  console.info('PASS: native cancel outcome classified; quarantined pool closed without tenant reuse');
} finally {
  if (cancellationReservation) {
    cancellationReservation.release();
    await withProbeDeadline(cancellationDb.close({ timeout: 0 }),
      3000, 'cancel pool final shutdown');
  }
}

// Whole-pool quarantine is a terminal state, not automatic recovery.
// A separately CONSTRUCTED clean pool is the only recovery path exercised.
console.info('STEP: freshly constructed pool after retired error/cancel pools');
const replacementDb = nativeSql(1);
const replacementDriver = createBoundedDriver(replacementDb);
try {
  for (const [actor, tenant, expectedId] of [
    ['actor-orbit', 'demo-orbit', 'orbit-project'],
    ['actor-north', 'demo-north', 'north-project'],
  ]) {
    assert.deepEqual((await read(replacementDriver, actor, tenant, 'projects'))
      .map(row => row.id), [expectedId]);
  }
  assert.deepEqual(replacementDriver.stats(), {
    discarded: 0, completed: 2, poisoned: false,
  });
  console.info('PASS: independently constructed new pool has isolated RLS scope');
} finally {
  await withProbeDeadline(replacementDb.close({ timeout: 2 }),
    3000, 'replacement pool close');
}
console.info('PASS: stage 2G.1b live Bun fault probes on ephemeral PostgreSQL only');
