/**
 * Backend 07: independent PostgreSQL16 physical PID evidence in disposable CI.
 * No live Railway service, production credentials, schema migration or data.
 */
import assert from 'node:assert/strict';
import {SQL} from 'bun';
import {createPgDurableIdentitySessionAuthority} from
  '../../src/features/saasBlueprint/controlApi/server/pgDurableIdentitySessionAuthority.ts';
import {createCiIsolatedIdentityPool} from './ci-isolated-identity-pool.mjs';

const env = process.env;
if (env.GITHUB_ACTIONS !== 'true' ||
    env.SAAS_ISOLATED_IDENTITY_DISCARD_CI !== 'true' ||
    env.PGHOST !== '127.0.0.1' ||
    env.PGPORT !== '5432' ||
    env.PGDATABASE !== 'saas_ephemeral_test' ||
    env.PGUSER !== 'postgres' ||
    env.NODE_ENV === 'production' ||
    env.RAILWAY_PROJECT_ID || env.RAILWAY_ENVIRONMENT ||
    env.RAILWAY_SERVICE_ID) {
  throw new Error('Physical identity PID proof is disposable PG16 CI only');
}
const password = env.SAAS_EPHEMERAL_IDENTITY_DB_PASSWORD;
if (!/^[0-9a-f]{48}$/.test(password ?? '')) {
  throw new Error('Missing ephemeral identity login credential');
}
delete env.SAAS_EPHEMERAL_IDENTITY_DB_PASSWORD;

const admin = new SQL({
  hostname: '127.0.0.1', port: 5432, database: 'saas_ephemeral_test',
  username: 'postgres', password: 'ci_ephemeral_test_only',
  max: 1, connectionTimeout: 5, idleTimeout: 5,
  prepare: false, tls: false,
});
const observedPids = [];
const pools = [];
const absentIdentity = Object.freeze({
  issuer: 'https://issuer.ci-evidence.org/token',
  subject: 'ci-backend07-unknown-subject',
});
function newPool(fault = false) {
  const pool = createCiIsolatedIdentityPool({
    password,
    observeBackendPid(pid) {observedPids.push(pid);},
    simulateLostCommitAckOnce: fault,
  });
  pools.push(pool);
  return pool;
}
async function pidCount(pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  const rows = await admin.unsafe(
    'SELECT COUNT(*)::integer AS active FROM pg_stat_activity WHERE pid=$1::integer',
    [pid]
  ).execute();
  assert.equal(rows.length, 1);
  return rows[0].active;
}
async function assertPhysicallyGone(pid) {
  for (let i = 0; i < 35; i++) {
    if ((await pidCount(pid)) === 0) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.fail('Retired physical identity PG backend still visible in pg_stat_activity');
}

try {
  const role = await admin.unsafe(
    "SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles " +
    "WHERE rolname='saas_identity_ci'"
  ).execute();
  assert.equal(role.length, 1);
  assert.deepEqual(
    [role[0].rolsuper, role[0].rolbypassrls, role[0].rolcanlogin],
    [false, false, true],
    'Identity login must never be a privileged PostgreSQL role'
  );

  console.info('STEP Backend07: successful read uses fixed private SQL role');
  const normal = newPool();
  const directory = createPgDurableIdentitySessionAuthority(normal).directory;
  assert.equal(await directory.resolveActorId(absentIdentity), null);
  const normalPid = observedPids.at(-1);
  assert.equal(await pidCount(normalPid), 1,
    'Before close a distinct physical identity backend must exist');
  assert.deepEqual(normal.stats(), {
    poisoned: false, active: 0, actualCommitAcks: 1, syntheticLostAcks: 0,
  });
  await normal.close();
  await assertPhysicallyGone(normalPid);
  await assert.rejects(normal.connect(new AbortController().signal));
  console.info('PASS Backend07: healthy identity pool cleanly retired; backend PID absent');

  console.info('STEP Backend07: actual PostgreSQL COMMIT with lost local ACK');
  const faulted = newPool(true);
  const faultDirectory = createPgDurableIdentitySessionAuthority(faulted).directory;
  await assert.rejects(
    faultDirectory.resolveActorId(absentIdentity),
    /Durable identity source unavailable/
  );
  const faultPid = observedPids.at(-1);
  assert.deepEqual(faulted.stats(), {
    poisoned: true, active: 0, actualCommitAcks: 1, syntheticLostAcks: 1,
  });
  await assertPhysicallyGone(faultPid);
  await assert.rejects(faulted.connect(new AbortController().signal));
  // No retry, no second COMMIT or reservation on the retired pool.
  assert.equal(faulted.stats().actualCommitAcks, 1);
  await faulted.close();
  console.info('PASS Backend07: lost-after-COMMIT local ACK poisons pool, physical PID gone');

  console.info('STEP Backend07: recover with wholly new independent pool');
  const fresh = newPool();
  const freshDirectory = createPgDurableIdentitySessionAuthority(fresh).directory;
  assert.equal(await freshDirectory.resolveActorId(absentIdentity), null);
  const freshPid = observedPids.at(-1);
  assert.notEqual(freshPid, faultPid,
    'New pool must create a different PostgreSQL backend');
  assert.equal(await pidCount(freshPid), 1);
  assert.equal(fresh.stats().actualCommitAcks, 1);
  assert.equal(fresh.stats().syntheticLostAcks, 0);
  await fresh.close();
  await assertPhysicallyGone(freshPid);
  console.info('PASS Backend07: fresh non-superuser pool works without reusing faulted backend');
} finally {
  await Promise.allSettled(pools.map(pool => pool.close()));
  await admin.close({timeout: 0});
}
console.info('PASS Backend07: real PG16 identity physical connection discard, CI ONLY');
