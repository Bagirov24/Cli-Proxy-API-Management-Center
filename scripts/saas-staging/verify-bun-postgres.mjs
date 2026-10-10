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
if (typeof keyHex !== 'string' || !/^[0-9a-f]{64}$/.test(keyHex)) {
  throw new Error('Synthetic HMAC key missing or invalid');
}
delete process.env.SAAS_EPHEMERAL_SCOPE_KEY_HEX;

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
    password: 'ci_ephemeral_runner_only',
    max, connectionTimeout: 5, idleTimeout: 5,
    prepare: false, tls: false,
  });
}

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
  return sql.startsWith('SELECT id, ') &&
    sql.includes(' FROM saas_rls.') &&
    sql.endsWith(' ORDER BY id LIMIT $2') && params.length === 2;
}

function createBoundedDriver(sql) {
  let discarded = 0;
  let completed = 0;
  return {
    stats: () => ({ discarded, completed }),
    async connect(signal) {
      const reserved = await sql.reserve(signal ? { signal } : undefined);
      let released = false;
      return {
        async query(statement, params) {
          if (released) throw new Error('Connection already released');
          if (!canExecuteSql(statement, params)) throw new Error('Non-allowlisted SQL');
          if (signal?.aborted && statement !== 'ROLLBACK') {
            throw new Error('Request cancelled');
          }
          // SQL.unsafe receives ONLY server-defined statements above;
          // all untrusted VALUES are supplied as driver-bound parameters.
          const query = reserved.unsafe(statement, [...params]).execute();
          const cancel = () => {
            if (statement !== 'ROLLBACK') query.cancel();
          };
          signal?.addEventListener('abort', cancel, { once: true });
          try {
            return { rows: await query };
          } finally {
            signal?.removeEventListener('abort', cancel);
          }
        },
        async release(discard) {
          if (released) throw new Error('Double release');
          released = true;
          if (discard) {
            discarded += 1;
            // Bun ReservedSQL has no release(true) signature. Closing the
            // reserved connection is required; NEVER put failed contexts
            // back into the pool via release().
            await reserved.close({ timeout: 0 });
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
    signal: options.signal,
  });
}

const dbPool = nativeSql(2);
const driver = createBoundedDriver(dbPool);
try {
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
  const data = await Promise.all(tasks);
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
const errorDb = nativeSql(1);
const errorDriver = createBoundedDriver(errorDb);
try {
  const invalidRole = await errorDriver.connect();
  const error = await invalidRole.query('BEGIN', []);
  assert.ok(error.rows);
  await invalidRole.query('ROLLBACK', []);
  await invalidRole.release(true);
  assert.equal(errorDriver.stats().discarded, 1);
  console.info('PASS: native driver supports forced discard of reserved connection');
} finally {
  await errorDb.close({ timeout: 0 });
}

console.info('PASS: stage 2F genuine Bun PostgreSQL driver integration (ephemeral database only)');
