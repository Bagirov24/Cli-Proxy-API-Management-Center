/**
 * Stage 2G.4a — real PostgreSQL RLS + synthetic signed JWT + synchronous audit.
 * CI-ONLY, no HTTP, OIDC discovery, production SQL, Core/Gateway or egress.
 * Every database read uses the non-superuser saas_ci_runner and fixed SELECTs.
 */
import assert from 'node:assert/strict';
import { SQL } from 'bun';
import { createPinnedAccessTokenVerifier } from
  '../../src/features/saasBlueprint/controlApi/server/trustedAccessToken.ts';
import { createTrustedSqlReadBoundary, createTrustedSqlPublishedBoundary } from
  '../../src/features/saasBlueprint/controlApi/server/trustedSqlReadBoundary.ts';
import { createPinnedHmacScopeIssuer, CONTROL_READ_SELECT_SQL, SCOPED_READ_GATE_SQL,
  SCOPED_AUTHORIZATION_REVISION_SQL, SCOPED_PUBLICATION_BARRIER_SQL,
  withSignedScopedPublicationBarrier } from
  '../../src/features/saasBlueprint/controlApi/server/signedSqlBoundary.ts';
import { createSecurityAuditRecorder, createSyntheticAuditBuffer } from
  '../../src/features/saasBlueprint/controlApi/server/securityAudit.ts';
import { createSignedPgAuthorizationRevisionSource } from
  '../../src/features/saasBlueprint/controlApi/server/signedPgAuthorizationRevision.ts';
import { captureServerAuthorizationRevision } from
  '../../src/features/saasBlueprint/controlApi/server/authorizationRevision.ts';

const ciOnly = process.env.GITHUB_ACTIONS === 'true' &&
  process.env.SAAS_EPHEMERAL_E2E_CI === 'true' &&
  process.env.NODE_ENV !== 'production' &&
  process.env.PGHOST === '127.0.0.1' &&
  process.env.PGPORT === '5432' &&
  process.env.PGDATABASE === 'saas_ephemeral_test' &&
  !process.env.RAILWAY_ENVIRONMENT &&
  !process.env.RAILWAY_PROJECT_ID;
if (!ciOnly) throw new Error('Refusing SaaS E2E outside ephemeral PG16 CI');

const keyHex = process.env.SAAS_EPHEMERAL_SCOPE_KEY_HEX;
const password = process.env.SAAS_EPHEMERAL_DB_PASSWORD;
if (typeof keyHex !== 'string' || !/^[0-9a-f]{64}$/.test(keyHex) ||
    typeof password !== 'string' || !/^[0-9a-f]{48}$/.test(password)) {
  throw new Error('Ephemeral scope key or non-superuser password unavailable');
}
delete process.env.SAAS_EPHEMERAL_SCOPE_KEY_HEX;
delete process.env.SAAS_EPHEMERAL_DB_PASSWORD;
const secretBytes = Uint8Array.from(Buffer.from(keyHex, 'hex'));
const hmacKey = await crypto.subtle.importKey(
  'raw', secretBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
);
secretBytes.fill(0);
const signer = createPinnedHmacScopeIssuer(hmacKey);

function nativeSql(max) {
  return new SQL({
    hostname: '127.0.0.1', port: 5432, database: 'saas_ephemeral_test',
    username: 'saas_ci_runner', password,
    max, connectionTimeout: 5, idleTimeout: 5, prepare: false, tls: false,
  });
}

const FIXED = new Set([
  'BEGIN', 'COMMIT', 'ROLLBACK',
  'SELECT txid_current()::text AS transaction_id',
  'SELECT set_config($1::text, $2::text, true)',
  'SET LOCAL ROLE saas_rls_reader',
]);
const SELECTS = new Set(Object.values(CONTROL_READ_SELECT_SQL));
function safeStatement(sql, params) {
  return typeof sql === 'string' && Array.isArray(params) &&
    (FIXED.has(sql) && (sql === 'SELECT set_config($1::text, $2::text, true)'
      ? params.length === 2 : params.length === 0) ||
     SELECTS.has(sql) && params.length === 2 ||
     sql === SCOPED_READ_GATE_SQL && params.length === 4 ||
     sql === SCOPED_AUTHORIZATION_REVISION_SQL && params.length === 4 ||
     sql === SCOPED_PUBLICATION_BARRIER_SQL && params.length === 4);
}

/** A disposable adapter, NOT proof of per-connection Bun discard safety. */
function boundedDriver(sql) {
  let poisoned = false;
  let reservations = 0;
  let committed = 0;
  let discarded = 0;
  let afterCommit = null;
  let commitQueries = 0;
  let scheduledCommit = null;
  return {
    stats: () => ({ poisoned, reservations, committed, discarded }),
    afterNextCommit(callback) { afterCommit = callback; },
    afterNthCommit(count, callback) {
      if (!Number.isSafeInteger(count) || count < 1 || scheduledCommit) {
        throw new Error('Invalid staging-only scheduled COMMIT');
      }
      scheduledCommit = { at: commitQueries + count, callback };
    },
    quarantine() { poisoned = true; },
    async connect(signal) {
      if (poisoned) throw new Error('Quarantined CI pool');
      const reserved = await sql.reserve(signal ? { signal } : undefined);
      if (poisoned) {
        reserved.release();
        throw new Error('Quarantined CI pool');
      }
      reservations += 1;
      let released = false;
      return {
        async query(statement, params, querySignal = signal) {
          if (released || !safeStatement(statement, params)) {
            throw new Error('Unsafe/disallowed staging query');
          }
          if (querySignal?.aborted && statement !== 'ROLLBACK') {
            throw new Error('Staging query aborted');
          }
          const pending = reserved.unsafe(statement, [...params]).execute();
          const cancel = () => {
            if (statement !== 'ROLLBACK') pending.cancel();
          };
          querySignal?.addEventListener('abort', cancel, { once: true });
          try {
            const rows = await pending;
            if (statement === 'COMMIT') {
              commitQueries += 1;
              const callback = afterCommit;
              afterCommit = null;
              callback?.(); // deterministic race AFTER real DB COMMIT
              if (scheduledCommit && scheduledCommit.at === commitQueries) {
                const scheduled = scheduledCommit.callback;
                scheduledCommit = null;
                scheduled(); // post-COMMIT fixture writer; never client SQL
              }
            }
            return { rows };
          } finally {
            querySignal?.removeEventListener('abort', cancel);
          }
        },
        async release(discard) {
          if (released) throw new Error('Double release');
          released = true;
          if (discard) {
            discarded += 1;
            poisoned = true;
            reserved.release();
            // No individual atomic Bun.SQL discard API was verified in 2G.1.
            // Destroy the WHOLE CI-only pool, never let another tenant reuse.
            await sql.close({ timeout: 0 });
          } else {
            committed += 1;
            reserved.release();
          }
        },
      };
    },
  };
}

/**
 * PRIVILEGED FIXTURE MUTATIONS, not part of the SaaS read boundary.
 * Runs only in the GitHub Actions disposable PostgreSQL under the existing
 * CI postgres bootstrap. All arguments are allowlisted here (not client SQL).
 * The application SQL connections remain non-superuser saas_ci_runner.
 */
function changeEphemeralFixture(action) {
  const statements = {
    suspendNorth: "UPDATE saas_rls.tenants SET status='suspended' WHERE id='demo-north' AND status='active'",
    restoreNorth: "UPDATE saas_rls.tenants SET status='active' WHERE id='demo-north' AND status='suspended'",
    revokeNorth: "UPDATE saas_rls.memberships SET status='revoked' WHERE actor_id='actor-north' AND tenant_id='demo-north' AND status='active'",
    restoreNorthMembership: "UPDATE saas_rls.memberships SET status='active' WHERE actor_id='actor-north' AND tenant_id='demo-north' AND status='revoked'",
    disableSharedAccount: "UPDATE saas_rls.resource_grants SET status='disabled' WHERE id='grant-account' AND grantee_tenant_id='demo-north' AND status='active'",
    restoreSharedAccount: "UPDATE saas_rls.resource_grants SET status='active' WHERE id='grant-account' AND grantee_tenant_id='demo-north' AND status='disabled'",
    expireSharedAccountSoon: "UPDATE saas_rls.resource_grants SET expires_at=clock_timestamp()+interval '3500 milliseconds' WHERE id='grant-account' AND grantee_tenant_id='demo-north' AND status='active'",
    restoreSharedAccountExpiry: "UPDATE saas_rls.resource_grants SET expires_at=NULL WHERE id='grant-account' AND grantee_tenant_id='demo-north'",
    waitWithoutAuthorizationWrite: "SELECT pg_sleep(4.2)",
    restorePoolAfterPublication: "UPDATE saas_rls.resource_grants SET status='active' WHERE id='grant-pool' AND grantee_tenant_id='demo-north' AND status='disabled'",
  };
  if (!Object.prototype.hasOwnProperty.call(statements, action)) {
    throw new Error('Unrecognized staging-only fixture mutation');
  }
  // No password or SQL output is logged. PGUSER/PGPASSWORD are fixed in
  // the ephemeral PG workflow; neither comes from a SaaS client.
  const outcome = Bun.spawnSync(
    ['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-q', '-c', statements[action]],
    { stdout: 'ignore', stderr: 'ignore' }
  );
  assert.equal(outcome.exitCode, 0, 'Disposable PG16 fixture mutation failed');
}

function readEphemeralNorthEpoch() {
  const outcome = Bun.spawnSync(
    ['psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c',
      "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'"],
    { stderr: 'ignore' }
  );
  assert.equal(outcome.exitCode, 0, 'Private disposable epoch unavailable');
  const revision = Buffer.from(outcome.stdout).toString('utf8').trim();
  assert.match(revision, /^[1-9][0-9]*$/);
  return revision;
}

const issuer = 'https://synthetic-staging-issuer.example.test/oauth';
const audience = 'saas-control-api';
const rsa = await crypto.subtle.generateKey({
  name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
}, true, ['sign', 'verify']);

function b64(value) {
  return Buffer.from(value).toString('base64url');
}
async function token(subject, claims = {}, header = {}) {
  const h = b64(JSON.stringify({
    typ: 'at+jwt', alg: 'RS256', kid: 'e2e-ephemeral', ...header,
  }));
  const current = Math.floor(Date.now() / 1000);
  const body = b64(JSON.stringify({
    iss: issuer, aud: audience, sub: subject,
    iat: current - 20, exp: current + 120, ...claims,
  }));
  const payload = new TextEncoder().encode(h + '.' + body);
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', rsa.privateKey, payload);
  return h + '.' + body + '.' + b64(Buffer.from(signature));
}
const verifier = createPinnedAccessTokenVerifier({
  issuer, audience,
  publicKeys: new Map([['e2e-ephemeral', rsa.publicKey]]),
});

const member = (tenantId, role, status = 'active') => ({ tenantId, role, status });
const actors = new Map([
  ['actor-north', {
    id: 'actor-north', memberships: [member('demo-north', 'tenant-admin')],
  }],
  ['actor-orbit', {
    id: 'actor-orbit', memberships: [member('demo-orbit', 'tenant-viewer')],
  }],
  ['actor-auditor', {
    id: 'actor-auditor', memberships: [member('demo-north', 'tenant-auditor')],
  }],
  ['actor-paused', {
    id: 'actor-paused', memberships: [member('demo-paused', 'tenant-owner')],
  }],
  ['actor-db-revoked', {
    id: 'actor-db-revoked', memberships: [member('demo-north', 'tenant-viewer')],
  }],
]);
const directory = new Map([
  [issuer + ':sub-north', 'actor-north'],
  [issuer + ':sub-orbit', 'actor-orbit'],
  [issuer + ':sub-auditor', 'actor-auditor'],
  [issuer + ':sub-paused', 'actor-paused'],
  [issuer + ':sub-db-revoked', 'actor-db-revoked'],
]);
const sink = createSyntheticAuditBuffer(128);
const audit = createSecurityAuditRecorder(sink, { classification: 'staging' });
let nextCorrelation = 0;

function createTrustedDependencies(pool, selectedAudit = audit, revisions = undefined) {
  return {
    tokens: verifier,
    actorDirectory: {
      async resolveActorId(identity) {
        return directory.get(identity.issuer + ':' + identity.subject) ?? null;
      },
    },
    actors: {
      async lookup(actorId, signal) {
        if (signal.aborted) throw new Error('Synthetic actor lookup aborted');
        return actors.get(actorId) ?? null;
      },
    },
    pool, signer, audit: selectedAudit, revisions,
    newCorrelationId: () => 'ci-e2e-' + (++nextCorrelation),
  };
}

function createRead(pool, selectedAudit = audit, revisions = undefined) {
  return createTrustedSqlReadBoundary(
    createTrustedDependencies(pool, selectedAudit, revisions)
  );
}

function request(accessToken, tenantId, collection = 'projects', options = {}) {
  return {
    accessToken, tenantId, collection,
    signal: options.signal ?? AbortSignal.timeout(15000),
    limit: options.limit ?? 30,
  };
}

function assertAudit(result, { reason, actorId, tenantId }) {
  const event = sink.snapshot().at(-1);
  assert.ok(event);
  assert.equal(event.correlationId, result.correlationId);
  assert.equal(event.classification, 'staging');
  assert.equal(event.source, 'trusted-sql-read-boundary');
  assert.equal(event.operation, 'saas.metadata.read');
  assert.equal(event.reason, reason);
  assert.equal(event.actorId, actorId);
  assert.equal(event.tenantId, tenantId);
  assert.equal(event.result, result.ok ? 'allow' :
    result.status === 503 ? 'error' : 'deny');
}

function visibleIds(result, label) {
  assert.equal(result.ok, true, label);
  assert.equal(result.status, 200);
  assert.equal(result.source, 'staging-signed-rls');
  assert.ok(Array.isArray(result.rows));
  const safe = JSON.stringify(result);
  for (const prohibited of ['password', 'refresh_token', 'oauth_secret',
    'api_key_secret', 'proxy_userinfo', 'prompt_text']) {
    assert.equal(safe.includes(prohibited), false, 'Secret material in metadata');
  }
  return result.rows.map(row => row.id).sort();
}

console.info('STEP: full synthetic JWT -> non-superuser PostgreSQL RLS -> audit');
const db = nativeSql(2);
const driver = boundedDriver(db);
const read = createRead(driver);
const north = await token('sub-north');
const orbit = await token('sub-orbit');
const auditor = await token('sub-auditor');
try {
  const northProjects = await read(request(north, 'demo-north'));
  assert.deepEqual(visibleIds(northProjects, 'North projects'), ['north-project']);
  assert.deepEqual(Object.keys(northProjects.rows[0]).sort(),
    ['id', 'name', 'status', 'tenant_id']);
  assertAudit(northProjects, {
    reason: 'read-allowed', actorId: 'actor-north', tenantId: 'demo-north',
  });
  const orbitProjects = await read(request(orbit, 'demo-orbit'));
  assert.deepEqual(visibleIds(orbitProjects, 'Orbit projects'), ['orbit-project']);
  assertAudit(orbitProjects, {
    reason: 'read-allowed', actorId: 'actor-orbit', tenantId: 'demo-orbit',
  });

  const concurrency = await Promise.all(Array.from({ length: 8 }, (_, index) =>
    read(request(index % 2 === 0 ? north : orbit,
      index % 2 === 0 ? 'demo-north' : 'demo-orbit'))
  ));
  for (let i = 0; i < concurrency.length; i += 1) {
    assert.deepEqual(visibleIds(concurrency[i], 'Concurrent RLS tenant isolation'),
      [i % 2 === 0 ? 'north-project' : 'orbit-project']);
  }
  assert.equal(driver.stats().poisoned, false);

  // SQL fixture supplies individual grants: North's Account grant remains
  // active while its Egress grant is disabled. Orbit gets Pool only, with an
  // expired Egress grant, NEVER the Pool's Account or Egress.
  const nAccounts = await read(request(north, 'demo-north', 'accounts'));
  assert.deepEqual(visibleIds(nAccounts, 'North account grants'),
    ['north-account', 'shared-account']);
  const nEgress = await read(request(north, 'demo-north', 'egress'));
  assert.deepEqual(visibleIds(nEgress, 'Account grant without Egress grant'),
    ['north-egress']);
  const oPools = await read(request(orbit, 'demo-orbit', 'pools'));
  assert.deepEqual(visibleIds(oPools, 'Orbit pool grants'),
    ['orbit-pool', 'shared-pool']);
  const oAccounts = await read(request(orbit, 'demo-orbit', 'accounts'));
  assert.deepEqual(visibleIds(oAccounts, 'Pool grant without Account grant'),
    ['orbit-account']);
  const oEgress = await read(request(orbit, 'demo-orbit', 'egress'));
  assert.deepEqual(visibleIds(oEgress, 'Expired Egress grant'),
    ['orbit-egress']);
  const bindings = await read(request(north, 'demo-north', 'routing'));
  assert.deepEqual(visibleIds(bindings, 'CPA-only routing'),
    ['north-route', 'north-shared']);
  assert.equal(JSON.stringify(bindings).includes('north-native'), false);
  console.info('PASS: distinct Pool, Account, Egress and CPA routing grants enforced by RLS');

  // A client-supplied JWT role, actor, tenant, header-like field or SQL-like
  // input never becomes a trusted actor scope or a SQL query.
  const beforeDenied = driver.stats().reservations;
  const forged = await token('sub-north', {
    role: 'tenant-owner', actorId: 'actor-orbit', tenantId: 'demo-orbit',
  });
  for (const [bearer, tenantId, collection, status, reason, actorId] of [
    [forged, 'demo-orbit', 'projects', 404, 'tenant-hidden', 'actor-north'],
    [orbit, 'demo-north', 'projects', 404, 'tenant-hidden', 'actor-orbit'],
    [auditor, 'demo-north', 'accounts', 403, 'role-forbidden', 'actor-auditor'],
    [await token('sub-north', { aud: 'not-this-api' }),
      'demo-north', 'projects', 401, 'unauthenticated', null],
    [await token('sub-north', {}, { typ: 'JWT' }),
      'demo-north', 'projects', 401, 'unauthenticated', null],
    [await token('sub-north', { iss: 'https://untrusted.example.test' }),
      'demo-north', 'projects', 401, 'unauthenticated', null],
    [await token('sub-north', {}, { kid: 'unknown-key' }),
      'demo-north', 'projects', 401, 'unauthenticated', null],
    [await token('sub-unknown'),
      'demo-north', 'projects', 401, 'unauthenticated', null],
    [north, "demo-north'; DROP TABLE saas_rls.projects; --",
      'projects', 404, 'invalid-request', null],
  ]) {
    const result = await read(request(bearer, tenantId, collection));
    assert.equal(result.ok, false);
    assert.equal(result.status, status);
    assert.equal('rows' in result, false);
    assert.equal('tenantId' in result, false);
    assertAudit(result, { reason, actorId, tenantId: null });
    assert.equal(JSON.stringify(result).includes('orbit-project'), false);
    assert.equal(JSON.stringify(sink.snapshot()).includes('DROP TABLE'), false);
  }
  assert.equal(driver.stats().reservations, beforeDenied);
  console.info('PASS: IDOR, wrong access-token, auditor and malicious input deny before SQL');

  // E2E 2G.4b: synthetic actor snapshot says "active" but PostgreSQL is
  // authoritative. Suspended tenant, revoked DB membership, and DB role
  // mismatch all cause generic 404 instead of a successful empty 200.
  const paused = await token('sub-paused');
  const dbRevoked = await token('sub-db-revoked');
  for (const [bearer, tenantId, actorId] of [
    [paused, 'demo-paused', 'actor-paused'],
    [dbRevoked, 'demo-north', 'actor-db-revoked'],
  ]) {
    const result = await read(request(bearer, tenantId, 'projects'));
    assert.equal(result.ok, false);
    assert.equal(result.status, 404);
    assert.equal('rows' in result, false);
    assert.equal('tenantId' in result, false);
    assertAudit(result, {
      reason: 'authorization-changed', actorId, tenantId: null,
    });
    assert.equal(driver.stats().poisoned, false);
  }
  // The database role for auditor is viewer-restricted. Simulate a stale
  // server-side claim to tenant-admin: project SELECT could pass old RLS
  // but the exact membership-role attestation must reject it.
  actors.set('actor-auditor', {
    id: 'actor-auditor',
    memberships: [member('demo-north', 'tenant-admin')],
  });
  const mismatchedRole = await read(request(auditor, 'demo-north', 'projects'));
  assert.equal(mismatchedRole.status, 404);
  assert.equal('rows' in mismatchedRole, false);
  assertAudit(mismatchedRole, {
    reason: 'authorization-changed', actorId: 'actor-auditor', tenantId: null,
  });
  actors.set('actor-auditor', {
    id: 'actor-auditor',
    memberships: [member('demo-north', 'tenant-auditor')],
  });
  assert.deepEqual(visibleIds(await read(request(orbit, 'demo-orbit')),
    'Healthy pool reuse after confirmed DB authz ROLLBACK'), ['orbit-project']);
  assert.equal(driver.stats().discarded, 0);
  console.info('PASS: suspended tenant, DB-revoked member and stale role deny 404 before output');

  const auditorAllowed = await read(request(auditor, 'demo-north', 'projects'));
  assert.deepEqual(visibleIds(auditorAllowed, 'Auditor allowed projects'),
    ['north-project']);

  // Deterministic revocation AFTER a genuine COMMIT, but before the
  // orchestration's second JWT and membership check. Real DB RLS is used;
  // server actor-store remains SYNTHETIC, not an atomic database snapshot.
  driver.afterNextCommit(() => {
    actors.set('actor-north', {
      id: 'actor-north',
      memberships: [member('demo-north', 'tenant-admin', 'revoked')],
    });
  });
  const revoked = await read(request(north, 'demo-north'));
  assert.equal(revoked.status, 404);
  assert.equal('rows' in revoked, false);
  assertAudit(revoked, {
    reason: 'authorization-changed', actorId: 'actor-north', tenantId: null,
  });
  actors.set('actor-north', {
    id: 'actor-north', memberships: [member('demo-north', 'tenant-admin')],
  });
  driver.afterNextCommit(() => { directory.delete(issuer + ':sub-north'); });
  const revokedMapping = await read(request(north, 'demo-north'));
  assert.equal(revokedMapping.status, 401);
  assert.equal('rows' in revokedMapping, false);
  assertAudit(revokedMapping, {
    reason: 'unauthenticated', actorId: 'actor-north', tenantId: null,
  });
  directory.set(issuer + ':sub-north', 'actor-north');

  // Stage 2G.4c: mutate the ACTUAL ephemeral PostgreSQL immediately AFTER
  // the first transaction has committed. The in-memory actor directory stays
  // unchanged, so only the NEW signed transaction can discover DB revocation.
  for (const scenario of [
    { change: 'suspendNorth', restore: 'restoreNorth', collection: 'projects' },
    { change: 'revokeNorth', restore: 'restoreNorthMembership', collection: 'projects' },
    { change: 'disableSharedAccount', restore: 'restoreSharedAccount', collection: 'accounts' },
  ]) {
    driver.afterNextCommit(() => changeEphemeralFixture(scenario.change));
    let decision;
    try {
      decision = await read(request(north, 'demo-north', scenario.collection));
      assert.equal(decision.ok, false);
      assert.equal(decision.status, 404);
      assert.equal('rows' in decision, false);
      assert.equal('tenantId' in decision, false);
      assertAudit(decision, {
        reason: 'authorization-changed', actorId: 'actor-north', tenantId: null,
      });
      const serialized = JSON.stringify(decision) + JSON.stringify(sink.snapshot());
      assert.equal(serialized.includes('shared-account'), false);
      assert.equal(serialized.includes('north-project'), false);
      assert.equal(driver.stats().poisoned, false);
    } finally {
      changeEphemeralFixture(scenario.restore);
    }
    assert.deepEqual(
      visibleIds(await read(request(orbit, 'demo-orbit')),
        'Unpoisoned Orbit access after post-COMMIT verification deny'),
      ['orbit-project']
    );
  }
  assert.equal(driver.stats().discarded, 0);
  console.info('PASS: after-COMMIT real PG16 tenant/member/grant revocation returns 404 and hides old rows');

  // Stage 2G.4d.3: ALL four signed transactions use the SAME real
  // non-superuser Bun.SQL driver: revision, metadata, metadata, revision.
  // Role, tenant, collection and actor are pinned by trusted server state.
  const revisionGuardedRead = createRead(
    driver, audit, createSignedPgAuthorizationRevisionSource(driver, signer)
  );
  const stableRevisionRead = await revisionGuardedRead(
    request(north, 'demo-north', 'projects', { limit: 1 })
  );
  assert.deepEqual(visibleIds(stableRevisionRead, 'PG revision-guarded stable North'),
    ['north-project']);
  assertAudit(stableRevisionRead, {
    reason: 'read-allowed', actorId: 'actor-north', tenantId: 'demo-north',
  });
  // No client/JWT-controlled revision can override signed PostgreSQL state.
  const forgedRevisionToken = await token('sub-north', {
    authorizationRevision: '9223372036854775807',
    role: 'tenant-owner', tenantId: 'demo-orbit',
  });
  const forgedRevisionRequest = {
    ...request(forgedRevisionToken, 'demo-north'),
    authorizationRevision: '9223372036854775807',
  };
  const forgedRevisionRead = await revisionGuardedRead(forgedRevisionRequest);
  assert.deepEqual(visibleIds(forgedRevisionRead, 'Client revision spoof ignored'),
    ['north-project']);
  assert.equal(JSON.stringify(forgedRevisionRead).includes('authorizationRevision'), false);
  assert.equal(JSON.stringify(sink.snapshot()).includes('9223372036854775807'), false);

  // COMMIT #1 captures a real signed revision; #2 and #3 commit unchanged
  // project rows. A privileged fixture writer changes an unrelated grant
  // AFTER metadata COMMIT #3; the final signed revision must reject even
  // though BOTH sanitized project reads were identical.
  for (const scenario of [
    { change: 'disableSharedAccount', restore: 'restoreSharedAccount',
      label: 'grant outside requested LIMIT' },
    { change: 'suspendNorth', restore: 'restoreNorth',
      label: 'tenant revoked after second metadata COMMIT' },
    { change: 'revokeNorth', restore: 'restoreNorthMembership',
      label: 'membership revoked before last signed revision' },
  ]) {
    driver.afterNthCommit(3, () => changeEphemeralFixture(scenario.change));
    try {
      const denied = await revisionGuardedRead(
        request(north, 'demo-north', 'projects', { limit: 1 })
      );
      assert.equal(denied.ok, false, scenario.label);
      assert.equal(denied.status, 404, scenario.label);
      assert.equal('rows' in denied, false);
      assert.equal('tenantId' in denied, false);
      assertAudit(denied, {
        reason: 'authorization-changed', actorId: 'actor-north', tenantId: null,
      });
      const safeText = JSON.stringify(denied) + JSON.stringify(sink.snapshot());
      assert.equal(safeText.includes('shared-account'), false);
      assert.equal(safeText.includes('north-project'), false);
      assert.equal(driver.stats().poisoned, false);
    } finally {
      changeEphemeralFixture(scenario.restore);
    }
    assert.deepEqual(visibleIds(
      await revisionGuardedRead(request(orbit, 'demo-orbit', 'projects')),
      'Orbit independent revision after North deny'
    ), ['orbit-project']);
  }
  assert.equal(driver.stats().discarded, 0);
  console.info('PASS: real PG16 signed revision detects after-second-COMMIT grant/tenant/member revoke');

  // A grant expires because TIME advances, not because a writer commits.
  // Both project SELECTs remain identical and the stored epoch remains
  // byte-for-byte unchanged between initial and final attestation.
  changeEphemeralFixture('expireSharedAccountSoon');
  const beforeExpiryEpoch = readEphemeralNorthEpoch();
  try {
    driver.afterNthCommit(3, () => {
      changeEphemeralFixture('waitWithoutAuthorizationWrite');
    });
    const timedOutGrant = await revisionGuardedRead(
      request(north, 'demo-north', 'projects', { limit: 1 })
    );
    assert.equal(timedOutGrant.status, 404);
    assert.equal('rows' in timedOutGrant, false);
    assertAudit(timedOutGrant, {
      reason: 'authorization-changed', actorId: 'actor-north', tenantId: null,
    });
    assert.equal(readEphemeralNorthEpoch(), beforeExpiryEpoch,
      'grant elapsed time MUST NOT increment the stored SQL epoch');
    assert.equal(driver.stats().poisoned, false);
  } finally {
    changeEphemeralFixture('restoreSharedAccountExpiry');
  }
  assert.deepEqual(visibleIds(
    await revisionGuardedRead(request(orbit, 'demo-orbit', 'projects')),
    'Orbit unaffected by North clock-only grant expiry'
  ), ['orbit-project']);
  console.info('PASS: real PG16 clock-only grant expiry denies unchanged rows and unchanged epoch');

  // Stage 2G.4d.5a: server-only publication proof on the real least-privilege
  // Bun.SQL pool. No HTTP network listener, bytes or user-controlled scope.
  // Publication baseline originates in trusted signed PG revision and the
  // payload is the already-sanitized result of trusted JWT+actor+RLS read.
  const publicationScope = Object.freeze({
    actorId: 'actor-north', tenantId: 'demo-north',
    role: 'tenant-admin', correlationId: 'ci-publication-proof',
  });
  const publicationSource = createSignedPgAuthorizationRevisionSource(driver, signer);
  const publicationBaseline = await captureServerAuthorizationRevision(
    publicationSource, publicationScope, 'projects', AbortSignal.timeout(5000)
  );
  const publishable = await revisionGuardedRead(
    request(north, 'demo-north', 'projects', { limit: 1 })
  );
  assert.deepEqual(visibleIds(publishable, 'Signed publication staging North'),
    ['north-project']);
  const publicationEvents = [];
  let publicationWriter = null;
  try {
    await withSignedScopedPublicationBarrier(driver, signer, {
      scope: publicationScope, collection: 'projects',
      baseline: publicationBaseline, timeoutMs: 7000,
      signal: AbortSignal.timeout(8000),
      handoff: {
        async prepare(signal) {
          assert.equal(signal.aborted, false);
          // External test writer runs as ephemeral Postgres fixture only,
          // never on the application pool or a client-defined query.
          publicationWriter = Bun.spawn({
            cmd: ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-c',
              "UPDATE saas_rls.resource_grants SET status='disabled' WHERE id='grant-pool' AND grantee_tenant_id='demo-north' AND status='active'"],
            env: { ...process.env, PGAPPNAME: 'ci_local_handoff_revoke' },
            stdout: 'ignore', stderr: 'ignore',
          });
          let blocked = false;
          for (let i = 0; i < 30; i++) {
            if (signal.aborted) throw new Error('Publication cancelled');
            const observation = Bun.spawnSync([
              'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c',
              "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='ci_local_handoff_revoke' AND wait_event_type='Lock'",
            ], { stderr: 'ignore' });
            assert.equal(observation.exitCode, 0);
            if (Buffer.from(observation.stdout).toString('utf8').trim() === '1') {
              blocked = true;
              break;
            }
            await Bun.sleep(80);
          }
          assert.equal(blocked, true, 'Revoke must block on signed shared epoch');
          assert.equal(publicationEvents.length, 0, 'prepare never publishes bytes');
          return () => {
            publicationEvents.push('local-handoff:' +
              publishable.rows.map(row => row.id).join(','));
          };
        },
      },
    });
    assert.deepEqual(publicationEvents, ['local-handoff:north-project']);
    assert.equal(await publicationWriter.exited, 0, 'Writer commits after handoff');
    assert.notEqual(readEphemeralNorthEpoch(), publicationBaseline.value,
      'Revocation must bump epoch after held publication transaction');
    let stalePrepared = false;
    await assert.rejects(withSignedScopedPublicationBarrier(driver, signer, {
      scope: publicationScope, collection: 'projects',
      baseline: publicationBaseline, timeoutMs: 4000,
      handoff: { async prepare() {
        stalePrepared = true;
        return () => { publicationEvents.push('STALE_HANDOFF'); };
      } },
    }), { name: 'ScopedSqlAuthorizationDenied' });
    assert.equal(stalePrepared, false);
    assert.deepEqual(publicationEvents, ['local-handoff:north-project']);
    assert.equal(driver.stats().poisoned, false);
  } finally {
    if (publicationWriter) {
      // The CI-only writer is required to finish before a fixture restore.
      assert.equal(await publicationWriter.exited, 0);
    }
    changeEphemeralFixture('restorePoolAfterPublication');
  }
  assert.deepEqual(visibleIds(
    await revisionGuardedRead(request(orbit, 'demo-orbit', 'projects')),
    'Orbit independent after completed publication revoke'
  ), ['orbit-project']);
  console.info('PASS: real PG16 signed local publication precedes revoke COMMIT; stale epoch cannot republish');

  // Stage 2G.4d.5b: a receipt-only API, where the actor/role/scope and
  // revision baseline are minted INSIDE trusted JWT->actor->RBAC. Only the
  // server-injected sink can stage local sanitized rows; no raw metadata
  // is returned to the caller, and audit must precede synchronous handoff.
  const trustedPublished = [];
  const publishRead = createTrustedSqlPublishedBoundary(
    createTrustedDependencies(driver, audit,
      createSignedPgAuthorizationRevisionSource(driver, signer)),
    {
      async stage(payload, signal) {
        assert.equal(signal.aborted, false);
        assert.equal(payload.tenantId, 'demo-north');
        assert.equal(payload.collection, 'projects');
        assert.deepEqual(payload.rows.map(row => row.id), ['north-project']);
        assert.equal(JSON.stringify(payload).includes('token_secret'), false);
        assert.equal(trustedPublished.length, 0, 'Private staging never emits data');
        const eventCount = sink.snapshot().length;
        return () => {
          assert.equal(sink.snapshot().length, eventCount + 1,
            'Fail-closed audit must succeed BEFORE local handoff');
          trustedPublished.push(payload.rows.map(row => row.id).join(','));
        };
      },
    }
  );
  const publicationReceipt = await publishRead(
    request(north, 'demo-north', 'projects', { limit: 1 })
  );
  assert.deepEqual(publicationReceipt.ok, true);
  assert.equal(publicationReceipt.status, 200);
  assert.equal(publicationReceipt.published, true);
  assert.equal('rows' in publicationReceipt, false);
  assert.equal('tenantId' in publicationReceipt, false);
  assert.equal(JSON.stringify(publicationReceipt).includes('north-project'), false);
  assert.deepEqual(trustedPublished, ['north-project']);
  assertAudit(publicationReceipt, {
    reason: 'read-allowed', actorId: 'actor-north', tenantId: 'demo-north',
  });
  const wrongTenantReceipt = await publishRead(
    request(north, 'demo-orbit', 'projects')
  );
  assert.equal(wrongTenantReceipt.status, 404);
  assert.equal('rows' in wrongTenantReceipt, false);
  assert.deepEqual(trustedPublished, ['north-project']);
  assert.equal(driver.stats().poisoned, false);
  console.info('PASS: trusted JWT/actor/RBAC/audit -> signed local publication yields receipt only');

  const brokenAudit = createSecurityAuditRecorder({
    write() { throw new Error('HIDDEN_TEST_ONLY_REFRESH_TOKEN'); },
  }, { classification: 'staging' });
  const failedAudit = await createRead(driver, brokenAudit)(
    request(north, 'demo-north'));
  assert.equal(failedAudit.status, 503);
  assert.equal('rows' in failedAudit, false);
  assert.equal(JSON.stringify(failedAudit).includes('HIDDEN_TEST_ONLY'), false);
  assert.equal(driver.stats().poisoned, false);
  console.info('PASS: post-COMMIT actor revocation and audit error discard SQL output');

  for (const event of sink.snapshot()) {
    if (event.result !== 'allow') assert.equal(event.tenantId, null);
    assert.equal(event.classification, 'staging');
  }
  const eventsText = JSON.stringify(sink.snapshot());
  for (const forbidden of [
    north, orbit, auditor, 'DROP TABLE', 'HIDDEN_TEST_ONLY',
    'shared-egress', 'orbit-project', 'proxy://', 'Authorization',
  ]) assert.equal(eventsText.includes(forbidden), false);
  assert.equal(driver.stats().discarded, 0);
} finally {
  if (!driver.stats().poisoned) await db.close({ timeout: 2 });
}

// Separate pool: abort only after real COMMIT, never return a stale result;
// a questionable Bun ReservedSQL is retired as a WHOLE pool.
console.info('STEP: abort during COMMIT of a real PG16 signed-scope read');
const cancellationDb = nativeSql(1);
const cancellationDriver = boundedDriver(cancellationDb);
const controller = new AbortController();
try {
  cancellationDriver.afterNextCommit(() => controller.abort());
  const stale = await createRead(cancellationDriver)(
    request(orbit, 'demo-orbit', 'projects', { signal: controller.signal })
  );
  assert.equal(stale.ok, false);
  assert.equal(stale.status, 503);
  assert.equal('rows' in stale, false);
  assertAudit(stale, {
    reason: 'request-cancelled', actorId: 'actor-orbit', tenantId: null,
  });
  assert.equal(cancellationDriver.stats().poisoned, true);
  await assert.rejects(cancellationDriver.connect());
  console.info('PASS: cancelled real SQL discards response and quarantines old pool');
} finally {
  if (!cancellationDriver.stats().poisoned) {
    await cancellationDb.close({ timeout: 0 });
  }
}
console.info('PASS: stage 2G.4a synthetic JWT through real ephemeral PG16 signed RLS + redacted audit');
