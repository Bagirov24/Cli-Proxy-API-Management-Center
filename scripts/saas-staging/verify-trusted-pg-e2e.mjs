/**
 * Stage 2G.4a — real PostgreSQL RLS + synthetic signed JWT + synchronous audit.
 * CI-ONLY, no HTTP, OIDC discovery, production SQL, Core/Gateway or egress.
 * Every database read uses the non-superuser saas_ci_runner and fixed SELECTs.
 */
import assert from 'node:assert/strict';
import { SQL } from 'bun';
import { createPinnedAccessTokenVerifier } from
  '../../src/features/saasBlueprint/controlApi/server/trustedAccessToken.ts';
import { createTrustedSqlReadBoundary } from
  '../../src/features/saasBlueprint/controlApi/server/trustedSqlReadBoundary.ts';
import { createPinnedHmacScopeIssuer, CONTROL_READ_SELECT_SQL } from
  '../../src/features/saasBlueprint/controlApi/server/signedSqlBoundary.ts';
import { createSecurityAuditRecorder, createSyntheticAuditBuffer } from
  '../../src/features/saasBlueprint/controlApi/server/securityAudit.ts';

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
     SELECTS.has(sql) && params.length === 2);
}

/** A disposable adapter, NOT proof of per-connection Bun discard safety. */
function boundedDriver(sql) {
  let poisoned = false;
  let reservations = 0;
  let committed = 0;
  let discarded = 0;
  let afterCommit = null;
  return {
    stats: () => ({ poisoned, reservations, committed, discarded }),
    afterNextCommit(callback) { afterCommit = callback; },
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
              const callback = afterCommit;
              afterCommit = null;
              callback?.(); // deterministic race AFTER real DB COMMIT
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
]);
const directory = new Map([
  [issuer + ':sub-north', 'actor-north'],
  [issuer + ':sub-orbit', 'actor-orbit'],
  [issuer + ':sub-auditor', 'actor-auditor'],
]);
const sink = createSyntheticAuditBuffer(128);
const audit = createSecurityAuditRecorder(sink, { classification: 'staging' });
let nextCorrelation = 0;

function createRead(pool, selectedAudit = audit) {
  return createTrustedSqlReadBoundary({
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
    pool, signer, audit: selectedAudit,
    newCorrelationId: () => 'ci-e2e-' + (++nextCorrelation),
  });
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
