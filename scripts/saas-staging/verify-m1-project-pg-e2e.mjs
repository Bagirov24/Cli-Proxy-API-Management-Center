/**
 * M1b: synthetic pinned RS256 -> server actor/role -> signed PG16 scope
 * -> fixed project function -> acknowledged COMMIT. GitHub disposable CI ONLY.
 *
 * NOT an HTTP backend, production driver, durable audit/outbox, OIDC service,
 * production physical discard, or real-network/replica COMMIT fencing.
 * No native Core/CPA key, remote signer, Railway or real user data is used.
 */
import assert from 'node:assert/strict';
import { SQL } from 'bun';
import { createM1ProjectCommandBoundary } from
  '../../src/features/saasBlueprint/controlApi/server/m1ProjectCommandBoundary.ts';
import { createPinnedAccessTokenVerifier } from
  '../../src/features/saasBlueprint/controlApi/server/trustedAccessToken.ts';
import { createPinnedHmacScopeIssuer } from
  '../../src/features/saasBlueprint/controlApi/server/signedSqlBoundary.ts';

const ciOnly = process.env.GITHUB_ACTIONS === 'true' &&
  process.env.SAAS_EPHEMERAL_M1_PG_CI === 'true' &&
  process.env.PGHOST === '127.0.0.1' &&
  process.env.PGPORT === '5432' &&
  process.env.PGDATABASE === 'saas_ephemeral_test' &&
  process.env.NODE_ENV !== 'production' &&
  !process.env.RAILWAY_PROJECT_ID && !process.env.RAILWAY_ENVIRONMENT;
if (!ciOnly) throw new Error('M1b driver test denied outside disposable PG16 GitHub CI');

const keyHex = process.env.SAAS_EPHEMERAL_SCOPE_KEY_HEX;
const dbPassword = process.env.SAAS_EPHEMERAL_DB_PASSWORD;
if (typeof keyHex !== 'string' || !/^[0-9a-f]{64}$/.test(keyHex) ||
    typeof dbPassword !== 'string' || !/^[0-9a-f]{48}$/.test(dbPassword)) {
  throw new Error('M1b missing ephemeral CI-only bootstrap');
}
delete process.env.SAAS_EPHEMERAL_SCOPE_KEY_HEX;
delete process.env.SAAS_EPHEMERAL_DB_PASSWORD;
const bytes = new Uint8Array(Buffer.from(keyHex, 'hex'));
const hmac = await crypto.subtle.importKey(
  'raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
);
bytes.fill(0);
const signer = createPinnedHmacScopeIssuer(hmac);

// Fixed templates only. Every tenant, ID, name and version is driver-bound.
const SQL_TEXT = Object.freeze({
  begin: 'BEGIN',
  commit: 'COMMIT',
  rollback: 'ROLLBACK',
  txid: 'SELECT txid_current()::text AS transaction_id',
  backend: 'SELECT pg_backend_pid()::int AS backend_pid',
  attempt: "SELECT set_config('saas.m1_attempt_id',$1::text,true) AS attempt_stamped",
  claim: 'SELECT set_config($1::text, $2::text, true)',
  role: 'SET LOCAL ROLE saas_m1_project_executor',
  create: 'SELECT saas_m1_api.create_project($1::text,$2::text,$3::text) AS applied',
  rename: 'SELECT saas_m1_api.rename_project($1::text,$2::text,$3::text,$4::bigint) AS applied',
  disable: 'SELECT saas_m1_api.disable_project($1::text,$2::text,$3::bigint) AS applied',
  read: 'SELECT project_id,name,status,version::text AS version FROM saas_m1_api.get_project($1::text,$2::text)',
});
const CLAIMS = new Set([
  'saas.scope_actor', 'saas.scope_tenant', 'saas.scope_txid',
  'saas.scope_expiry', 'saas.scope_mac',
]);
const FIXED_COUNTS = new Map([
  [SQL_TEXT.begin, 0], [SQL_TEXT.commit, 0], [SQL_TEXT.rollback, 0],
  [SQL_TEXT.txid, 0], [SQL_TEXT.backend, 0], [SQL_TEXT.role, 0],
  [SQL_TEXT.attempt, 1],
  [SQL_TEXT.create, 3], [SQL_TEXT.rename, 4],
  [SQL_TEXT.disable, 3], [SQL_TEXT.read, 2],
]);
const SAFE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const SAFE_ACTOR = /^[A-Za-z0-9_-]{1,128}$/;
const SAFE_UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function canQuery(statement, params) {
  if (statement === SQL_TEXT.claim) {
    return params.length === 2 && CLAIMS.has(params[0]) &&
      typeof params[1] === 'string';
  }
  return FIXED_COUNTS.has(statement) && FIXED_COUNTS.get(statement) === params.length;
}
function validateScope(scope) {
  return scope && SAFE_ACTOR.test(scope.actorId) && SAFE_ID.test(scope.tenantId) &&
    SAFE_ACTOR.test(scope.correlationId) &&
    (scope.role === 'tenant-admin' || scope.role === 'tenant-owner');
}
function makeNativeDb() {
  // No URL, hostname, database, user, TLS or port from the calling request.
  return new SQL({
    hostname: '127.0.0.1', port: 5432, database: 'saas_ephemeral_test',
    username: 'saas_ci_runner', password: dbPassword, max: 1,
    connectionTimeout: 5, idleTimeout: 5, prepare: false, tls: false,
  });
}
function makeDriver({ dropAckAfterCommit = false, beforeCommit, attemptTagging = false } = {}) {
  const db = makeNativeDb();
  let poisoned = false;
  let reservations = 0;
  let commitAcks = 0;
  let ackFault = dropAckAfterCommit;
  async function transaction(scope, operation, projectId, name, version, signal, attemptId) {
    if (poisoned || signal.aborted || !validateScope(scope) ||
        !SAFE_ID.test(projectId) ||
        !['create', 'rename', 'disable', 'read'].includes(operation)) {
      throw new Error('M1b transaction refused');
    }
    // A reserve error may leave pool state uncertain. Quarantine before
    // handling it. This whole-pool strategy is for CI, NOT production.
    let reserved;
    try {
      reserved = await db.reserve({ signal });
    } catch {
      poisoned = true;
      throw new Error('M1b reservation unavailable');
    }
    reservations += 1;
    if (poisoned || signal.aborted) {
      poisoned = true;
      reserved.release();
      await db.close({ timeout: 0 });
      throw new Error('M1b request cancelled');
    }

    let unsafe = false;
    const query = async (statement, params = []) => {
      if (!canQuery(statement, params) || signal.aborted) {
        throw new Error('M1b non-allowlisted or cancelled SQL');
      }
      const pending = reserved.unsafe(statement, [...params]).execute();
      const cancel = () => {
        if (statement !== SQL_TEXT.rollback) pending.cancel();
      };
      signal.addEventListener('abort', cancel, { once: true });
      try {
        return await pending;
      } finally {
        signal.removeEventListener('abort', cancel);
      }
    };
    try {
      await query(SQL_TEXT.begin);
      const assigned = await query(SQL_TEXT.txid);
      const txid = assigned[0]?.transaction_id;
      if (typeof txid !== 'string' || !/^[0-9]{1,19}$/.test(txid)) {
        throw new Error('M1b invalid transaction ID');
      }
      const now = Math.floor(Date.now() / 1000);
      if (!Number.isSafeInteger(now) || now < 1_000_000_000 ||
          now >= 9_999_999_900) throw new Error('M1b invalid clock');
      const expiry = now + 60;
      const mac = await signer.sign(scope, txid, expiry);
      if (!/^[a-f0-9]{64}$/.test(mac) || signal.aborted) {
        throw new Error('M1b signature unavailable');
      }
      const values = [
        ['saas.scope_actor', scope.actorId],
        ['saas.scope_tenant', scope.tenantId],
        ['saas.scope_txid', txid],
        ['saas.scope_expiry', String(expiry)],
        ['saas.scope_mac', mac],
      ];
      for (const pair of values) await query(SQL_TEXT.claim, pair);
      if (attemptTagging && operation !== 'read') {
        if (typeof attemptId !== 'string' || !SAFE_UUID_V4.test(attemptId)) {
          throw new Error('M1g missing server-minted UUIDv4 on signed write');
        }
        await query(SQL_TEXT.attempt, [attemptId]);
      }
      await query(SQL_TEXT.role);
      if (signal.aborted) throw new Error('M1b cancelled before operation');
      let params;
      if (operation === 'read') params = [scope.tenantId, projectId];
      else if (operation === 'create') params = [scope.tenantId, projectId, name];
      else if (operation === 'rename') params = [scope.tenantId, projectId, name, version];
      else params = [scope.tenantId, projectId, version];
      const rows = await query(SQL_TEXT[operation], params);
      if (operation === 'read') {
        if (!Array.isArray(rows) || rows.length > 1) {
          throw new Error('M1b malformed read');
        }
        await query(SQL_TEXT.commit);
        commitAcks += 1;
        return rows;
      }
      if (!Array.isArray(rows) || rows.length !== 1 ||
          typeof rows[0]?.applied !== 'boolean') {
        throw new Error('M1b malformed mutation acknowledgement');
      }
      if (!rows[0].applied) {
        // DENY is not a partially successful write: confirm ROLLBACK.
        await query(SQL_TEXT.rollback);
        return false;
      }
      // Optional fault hook is wired ONLY by explicit M1e disposable-CI
      // tests. It runs after a real signed SQL mutation and private audit
      // INSERT, but before the transaction attempts COMMIT.
      if (beforeCommit) {
        const probe = await query(SQL_TEXT.backend);
        const backendPid = probe[0]?.backend_pid;
        if (!Number.isSafeInteger(backendPid) || backendPid < 1) {
          throw new Error('M1e invalid physical PG backend identity');
        }
        await beforeCommit({ backendPid, signal });
      }
      if (signal.aborted) throw new Error('M1b cancelled before COMMIT');
      await query(SQL_TEXT.commit);
      if (ackFault) {
        // The actual PG COMMIT has completed, but the server deliberately
        // loses its local ACK. No reissue or automatic retry is permitted.
        ackFault = false;
        throw new Error('M1b CI-only simulated lost COMMIT acknowledgement');
      }
      commitAcks += 1;
      return true;
    } catch {
      // Even if COMMIT physically succeeded, return an UNKNOWN generic error.
      // Never retry or return a connection to another tenant after uncertainty.
      unsafe = true;
      poisoned = true; // synchronous quarantine before any await
      throw new Error('M1b transaction outcome unavailable');
    } finally {
      let released = false;
      try {
        reserved.release();
        released = true;
      } catch {
        poisoned = true;
      }
      if (unsafe || !released) {
        poisoned = true;
        await db.close({ timeout: 0 }); // entire disposable CI pool
      }
      if (!released) throw new Error('M1b release uncertain');
    }
  }
  return Object.freeze({
    async execute(input) {
      const { scope, operation, projectId, name, expectedVersion, signal, attemptId } = input;
      return transaction(scope, operation, projectId, name, expectedVersion, signal, attemptId);
    },
    read(scope, projectId, signal = AbortSignal.timeout(12000)) {
      return transaction(scope, 'read', projectId, undefined, undefined, signal);
    },
    stats() { return { poisoned, reservations, commitAcks }; },
    async close() { await db.close({ timeout: 0 }); },
  });
}

const issuer = 'https://synthetic-m1b-issuer.example.test/';
const audience = 'urn:saas-m1b-ci-only';
const rsa = await crypto.subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true, ['sign', 'verify']
);
const verifier = createPinnedAccessTokenVerifier({
  issuer, audience, publicKeys: new Map([['m1b-ephemeral-key', rsa.publicKey]]),
});
async function signToken(subject, overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({
    alg: 'RS256', typ: 'at+jwt', kid: 'm1b-ephemeral-key',
  })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: issuer, aud: audience, sub: subject, iat: now,
    exp: now + 300, ...overrides,
  })).toString('base64url');
  const body = header + '.' + payload;
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', rsa.privateKey, new TextEncoder().encode(body)
  );
  return body + '.' + Buffer.from(signature).toString('base64url');
}

const ids = Object.freeze({
  north: 'actor-north', orbit: 'actor-orbit', auditor: 'actor-auditor',
});
const role = Object.freeze({
  'actor-north': ['demo-north', 'tenant-admin'],
  'actor-orbit': ['demo-orbit', 'tenant-viewer'],
  'actor-auditor': ['demo-north', 'tenant-auditor'],
});
const directory = Object.freeze({
  async resolveActorId(identity) {
    if (identity.issuer !== issuer) return null;
    return ids[identity.subject] ?? null;
  },
});
const actors = Object.freeze({
  async lookup(actorId) {
    const membership = role[actorId];
    if (!membership) return null;
    return {
      id: actorId,
      memberships: [{
        tenantId: membership[0], role: membership[1], status: 'active',
      }],
    };
  },
});
function boundary(driver) {
  return createM1ProjectCommandBoundary({
    tokens: verifier, directory, actors, writer: driver,
    newCorrelationId: () => 'm1b-server-generated-correlation',
  });
}
function command(operation, token, projectId, extra = {}) {
  return {
    operation, accessToken: token, tenantId: 'demo-north', projectId,
    ...(operation === 'create' || operation === 'rename'
      ? { name: 'M1b CI-only Project' } : {}),
    ...(operation === 'rename' || operation === 'disable'
      ? { expectedVersion: 1 } : {}),
    signal: AbortSignal.timeout(12000), ...extra,
  };
}
const northScope = Object.freeze({
  actorId: 'actor-north', tenantId: 'demo-north',
  role: 'tenant-admin', correlationId: 'm1b-ci-internal-read',
});

const m1gOnly = process.env.SAAS_EPHEMERAL_M1G_ATTEMPT_CI === 'true';
if (m1gOnly && process.env.SAAS_EPHEMERAL_M1E_DISCONNECT_CI === 'true') {
  throw new Error('M1g CI attempt run must not re-execute earlier M1e fixtures');
}
if (!m1gOnly) {
console.info('STEP M1b: pinned synthetic RS256 identity and signed native PG16 command');
const north = await signToken('north');
const viewer = await signToken('orbit', {
  role: 'tenant-owner', actorId: 'actor-north', tenantId: 'demo-north',
});
const auditor = await signToken('auditor');
const wrongAudience = await signToken('north', { aud: 'urn:wrong-api' });
const driver = makeDriver();
try {
  const invoke = boundary(driver);
  assert.equal((await invoke(command('create', wrongAudience, 'm1b-bad-aud'))).status, 401);
  assert.equal((await invoke(command('create', viewer, 'm1b-viewer', {
    tenantId: 'demo-orbit',
  }))).status, 404);
  assert.equal((await invoke(command('create', auditor, 'm1b-auditor'))).status, 404);
  assert.equal((await invoke(command('create', north, 'm1b-first', {
    tenantId: 'demo-orbit',
  }))).status, 404);

  const created = await invoke(command('create', north, 'm1b-first'));
  assert.equal(created.status, 201);
  assert.equal((await invoke(command('create', north, 'm1b-first'))).status, 404);
  const rows = await driver.read(northScope, 'm1b-first');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].name, 'M1b CI-only Project');
  assert.equal(rows[0].version, '1');
  assert.equal((await invoke(command('rename', north, 'm1b-first', {
    name: 'M1b renamed',
  }))).status, 200);
  assert.equal((await invoke(command('rename', north, 'm1b-first', {
    name: 'stale CAS',
  }))).status, 404);
  assert.equal((await invoke(command('disable', north, 'm1b-first', {
    expectedVersion: 2,
  }))).status, 200);
  assert.equal((await invoke(command('rename', north, 'm1b-first', {
    name: 'must remain disabled', expectedVersion: 3,
  }))).status, 404);
  const terminal = await driver.read(northScope, 'm1b-first');
  assert.equal(terminal[0].status, 'disabled');
  assert.equal(terminal[0].version, '3');

  // Independent signed target-tenant denial is enforced by PostgreSQL.
  assert.equal((await driver.read(northScope, 'm1-orbit')).length, 0);
  assert.equal(driver.stats().poisoned, false);
} finally {
  await driver.close();
}

// The verified server actor snapshot can be stale; PostgreSQL must still
// reject a revoked DB membership inside the actual signed write transaction.
function setFixture(action) {
  const fixed = {
    revoke: "UPDATE saas_rls.memberships SET status='revoked' WHERE actor_id='actor-north' AND tenant_id='demo-north' AND status='active'",
    restore: "UPDATE saas_rls.memberships SET status='active' WHERE actor_id='actor-north' AND tenant_id='demo-north' AND status='revoked'",
  };
  assert.ok(Object.prototype.hasOwnProperty.call(fixed, action));
  const done = Bun.spawnSync(
    ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-c', fixed[action]],
    { stdout: 'ignore', stderr: 'ignore' }
  );
  assert.equal(done.exitCode, 0, 'M1b ephemeral fixture mutation failed');
}
const revokeDriver = makeDriver();
setFixture('revoke');
try {
  assert.equal((await boundary(revokeDriver)(
    command('create', north, 'm1b-revoked')
  )).status, 404);
  assert.equal(revokeDriver.stats().poisoned, false);
} finally {
  setFixture('restore');
  await revokeDriver.close();
}

// Test loss of local ACK AFTER an actual committed PG16 write. The caller
// sees generic 503, pool is quarantined, no retry occurs. A fresh healthy
// signed read may independently observe the committed project.
const faultDriver = makeDriver({ dropAckAfterCommit: true });
const lostAck = await boundary(faultDriver)(
  command('create', north, 'm1b-lost-ack')
);
assert.equal(lostAck.status, 503);
assert.equal(faultDriver.stats().poisoned, true);
assert.equal(faultDriver.stats().reservations, 1);
await faultDriver.close();
const observer = makeDriver();
try {
  const observed = await observer.read(northScope, 'm1b-lost-ack');
  assert.equal(observed.length, 1);
  assert.equal(observed[0].version, '1');
} finally {
  await observer.close();
}
console.info('PASS M1b: pinned RS256 -> trusted actor -> signed PG16 fixed-function CRUD; ' +
  'cross-tenant/role/stale CAS/revoked membership DENY; lost COMMIT ACK=503 + quarantine, NO retry/deploy');


// M1e is opt-in, synthetic and GitHub disposable-PG16 ONLY. The older
// M1b lost-ACK-after-committed-COMMIT case above remains independent:
// a caller's 503 alone never tells an operator whether PG committed.
if (process.env.SAAS_EPHEMERAL_M1E_DISCONNECT_CI === 'true') {
  console.info('STEP M1e: real physical PG backend loss and cancellation BEFORE COMMIT');

  function fixtureSql(statement) {
    // The SQL below is authored here, never sourced from user/JWT text.
    // The only dynamic scalar is a validated integer from pg_backend_pid().
    const result = Bun.spawnSync(
      ['psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', statement],
      { stdout: 'pipe', stderr: 'pipe' }
    );
    assert.equal(result.exitCode, 0, 'M1e privileged disposable PG fixture failed');
    return new TextDecoder().decode(result.stdout).trim();
  }
  function assertPhysicalSessionGone(pid) {
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    assert.equal(
      fixtureSql('SELECT COUNT(*)::int FROM pg_stat_activity WHERE pid=' + pid),
      '0', 'M1e damaged/cancelled reserved physical backend must disappear'
    );
  }

  // Loss path A: privileged independent CI connection physically terminates
  // the exact observed server backend AFTER signed create+audit, BEFORE COMMIT.
  // PG drops that entire uncommitted transaction. The user-facing boundary
  // must send generic 503 (never false success) and poison the entire pool.
  let terminatedPid = null;
  const terminatedDriver = makeDriver({
    beforeCommit({ backendPid }) {
      assert.ok(Number.isSafeInteger(backendPid) && backendPid > 0);
      terminatedPid = backendPid;
      assert.equal(fixtureSql(
        "SELECT CASE WHEN pg_terminate_backend(" + backendPid +
          ") THEN 'terminated' ELSE 'missing' END"
      ), 'terminated', 'M1e expected one real PG backend termination');
    },
  });
  try {
    const response = await boundary(terminatedDriver)(
      command('create', north, 'm1e-physical-loss')
    );
    assert.equal(response.status, 503);
    assert.equal(response.ok, false);
    assert.equal(response.error.code, 'SOURCE_UNAVAILABLE');
    assert.deepEqual(terminatedDriver.stats(), {
      poisoned: true, reservations: 1, commitAcks: 0,
    });
    assert.equal((await boundary(terminatedDriver)(
      command('create', north, 'm1e-reuse-denied')
    )).status, 503);
    assert.equal(terminatedDriver.stats().reservations, 1,
      'M1e a quarantined pool cannot reserve a second request');
  } finally {
    await terminatedDriver.close();
  }
  assertPhysicalSessionGone(terminatedPid);

  // Cancellation path B: abort AFTER successful transactional write+audit but
  // BEFORE COMMIT. An aborted request cannot commit or reuse its connection.
  const controller = new AbortController();
  let abortPid = null;
  const abortedDriver = makeDriver({
    beforeCommit({ backendPid }) {
      abortPid = backendPid;
      controller.abort('M1e synthetic cancellation before COMMIT');
    },
  });
  try {
    const response = await boundary(abortedDriver)(
      command('create', north, 'm1e-aborted', { signal: controller.signal })
    );
    assert.equal(response.status, 503);
    assert.equal(response.ok, false);
    assert.equal(abortedDriver.stats().poisoned, true);
    assert.equal(abortedDriver.stats().reservations, 1);
    assert.equal(abortedDriver.stats().commitAcks, 0);
    assert.equal((await boundary(abortedDriver)(
      command('create', north, 'm1e-abort-reuse-denied')
    )).status, 503);
    assert.equal(abortedDriver.stats().reservations, 1);
  } finally {
    await abortedDriver.close();
  }
  assertPhysicalSessionGone(abortPid);

  // Observer is a fresh signed SQL transaction, NOT a retry of a write.
  // A fixture superuser separately inspects private audit rows. Nothing
  // uncommitted is allowed to survive either physically terminated session.
  const healthyObserver = makeDriver();
  try {
    assert.equal((await healthyObserver.read(northScope, 'm1e-physical-loss')).length, 0);
    assert.equal((await healthyObserver.read(northScope, 'm1e-aborted')).length, 0);
    assert.equal(healthyObserver.stats().poisoned, false);
  } finally {
    await healthyObserver.close();
  }
  assert.equal(fixtureSql(
    "SELECT (SELECT COUNT(*) FROM saas_m1_private.projects " +
    "WHERE tenant_id='demo-north' AND project_id IN " +
    "('m1e-physical-loss','m1e-aborted','m1e-reuse-denied','m1e-abort-reuse-denied'))::text " +
    "|| ':' || (SELECT COUNT(*) FROM saas_m1_private.project_write_audit_outbox " +
    "WHERE tenant_id='demo-north' AND project_id IN " +
    "('m1e-physical-loss','m1e-aborted','m1e-reuse-denied','m1e-abort-reuse-denied'))::text"
  ), '0:0', 'M1e failed/aborted operation must leave no project OR private audit');
  assert.equal(fixtureSql(
    "SELECT (SELECT COUNT(*) FROM saas_m1_private.projects " +
    "WHERE project_id='m1b-lost-ack')::text || ':' || " +
    "(SELECT COUNT(*) FROM saas_m1_private.project_write_audit_outbox " +
    "WHERE project_id='m1b-lost-ack')::text"
  ), '1:1', 'M1b lost ACK AFTER committed PG COMMIT remains project+audit');

  console.info(
    'PASS M1e: real pg_terminate_backend BEFORE COMMIT and cancellation; ' +
    '503 + quarantine, physical PID gone, 0 project/0 audit, no repeat; ' +
    'M1b committed lost ACK remains 1 project/1 audit; NO PRODUCTION retry'
  );
}


}
if (m1gOnly) {
  // A completely separate invocation, AFTER SQL024 installation.
  // Real synthetic RS256 -> trusted issuer/subject -> M1a RBAC -> signed
  // PostgreSQL transaction; UUIDv4 is minted by this CI server wrapper
  // BEFORE its writer.execute call, never read from JWT or HTTP payload.
  console.info('STEP M1g: server-issued UUIDv4 on signed native project writes');
  const northToken = await signToken('north');
  const issued = [];
  function withServerAttempts(native) {
    return boundary(Object.freeze({
      async execute(input) {
        const attemptId = crypto.randomUUID();
        issued.push(Object.freeze({
          attemptId, operation: input.operation, projectId: input.projectId,
        }));
        return native.execute({ ...input, attemptId });
      },
    }));
  }
  function attemptFor(projectId, operation) {
    const row = issued.find(x => x.projectId === projectId && x.operation === operation);
    assert.ok(row && SAFE_UUID_V4.test(row.attemptId), 'M1g server minted attempt must exist');
    return row.attemptId;
  }
  const d = makeDriver({ attemptTagging: true });
  try {
    const invoke = withServerAttempts(d);
    assert.equal((await invoke(command('create', northToken, 'm1g-first'))).status, 201);
    const firstAttempt = attemptFor('m1g-first', 'create');
    assert.equal((await invoke(command('rename', northToken, 'm1g-first', {
      name: 'M1g renamed', expectedVersion: 1,
    }))).status, 200);
    assert.equal((await invoke(command('disable', northToken, 'm1g-first', {
      expectedVersion: 2,
    }))).status, 200);
    assert.equal((await invoke(command('rename', northToken, 'm1g-first', {
      name: 'No reactivation', expectedVersion: 3,
    }))).status, 404);
    const observed = await d.read(northScope, 'm1g-first');
    assert.equal(observed.length, 1);
    assert.equal(observed[0].status, 'disabled');
    assert.equal(observed[0].version, '3');

    // Deliberate server-side BUG simulation: the same already committed
    // attempt UUID used to mutate an unrelated project must be denied by
    // unique constraint, rolling back BOTH new project + its audit.
    const reused = await d.execute({
      scope: northScope, operation: 'create',
      projectId: 'm1g-reused-attempt',
      name: 'Must not commit', signal: AbortSignal.timeout(12000),
      attemptId: firstAttempt,
    });
    assert.equal(reused, false);
    assert.equal((await d.read(northScope, 'm1g-reused-attempt')).length, 0);

    // A legacy signed writer missing the server attempt stamp must also
    // fail closed after SQL024; never produce an unaudited mutation.
    const legacy = makeDriver();
    try {
      const skipped = await legacy.execute({
        scope: northScope, operation: 'create',
        projectId: 'm1g-no-stamp',
        name: 'Must not commit', signal: AbortSignal.timeout(12000),
      });
      assert.equal(skipped, false);
    } finally {
      await legacy.close();
    }
    assert.equal((await d.read(northScope, 'm1g-no-stamp')).length, 0);
    assert.equal(d.stats().poisoned, false);
  } finally {
    await d.close();
  }

  // Fresh distinct UUID and signed transaction: actual COMMIT succeeds,
  // local ACK is deliberately lost. The same originating caller sees 503;
  // NO retry. An independent reviewer can later find the specific UUID,
  // but the ID and receipt live in the same PG trust domain.
  const uncertain = makeDriver({
    attemptTagging: true, dropAckAfterCommit: true,
  });
  let uncertainId;
  try {
    const invoke = boundary({
      execute(input) {
        uncertainId = crypto.randomUUID();
        return uncertain.execute({ ...input, attemptId: uncertainId });
      },
    });
    const response = await invoke(command('create', northToken, 'm1g-lost-ack'));
    assert.equal(response.status, 503);
    assert.ok(SAFE_UUID_V4.test(uncertainId));
    assert.equal(uncertain.stats().poisoned, true);
    assert.equal(uncertain.stats().reservations, 1);
    assert.equal(uncertain.stats().commitAcks, 0);
  } finally {
    await uncertain.close();
  }
  const healthy = makeDriver();
  try {
    const record = await healthy.read(northScope, 'm1g-lost-ack');
    assert.equal(record.length, 1);
    assert.equal(record[0].version, '1');
  } finally {
    await healthy.close();
  }
  console.info(
    'PASS M1g: verified RS256 server-minted UUIDv4 binds same-COMMIT project/audit; ' +
    'committed duplicate attempt and missing stamp deny; lost ACK=503 with durable ' +
    'local UUID evidence, NO automatic retry, NO production'
  );
}
