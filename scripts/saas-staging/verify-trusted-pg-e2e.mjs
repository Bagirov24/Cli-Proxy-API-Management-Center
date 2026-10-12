/**
 * Stage 2G.4a — real PostgreSQL RLS + synthetic signed JWT + synchronous audit.
 * CI-ONLY, no HTTP, OIDC discovery, production SQL, Core/Gateway or egress.
 * Every database read uses the non-superuser saas_ci_runner and fixed SELECTs.
 */
import assert from 'node:assert/strict';
import { SQL } from 'bun';
import { createPinnedAccessTokenVerifier } from
  '../../src/features/saasBlueprint/controlApi/server/trustedAccessToken.ts';
import { createTrustedIssuerSessionProvisioner } from
  '../../src/features/saasBlueprint/controlApi/server/issuerSessionProvisioning.ts';
import { createTrustedSqlReadBoundary, createTrustedSqlPublishedBoundary } from
  '../../src/features/saasBlueprint/controlApi/server/trustedSqlReadBoundary.ts';
import { createTrustedSyntheticCommittedIntentBoundary } from
  '../../src/features/saasBlueprint/controlApi/server/syntheticCommittedIntent.ts';
import { createPinnedHmacScopeIssuer, CONTROL_READ_SELECT_SQL, SCOPED_READ_GATE_SQL,
  SCOPED_AUTHORIZATION_REVISION_SQL, SCOPED_PUBLICATION_BARRIER_SQL,
  SCOPED_PUBLICATION_OUTBOX_SQL, withSignedScopedPublicationBarrier } from
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
     sql === SCOPED_PUBLICATION_BARRIER_SQL && params.length === 4 ||
     sql === SCOPED_PUBLICATION_OUTBOX_SQL && params.length === 5);
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
    revokeNorthSession: "UPDATE saas_rls_private.actor_session_state SET status='revoked', revision=revision+1 WHERE actor_id='actor-north' AND status='active'",
    restoreNorthSession: "UPDATE saas_rls_private.actor_session_state SET status='active', revision=revision+1 WHERE actor_id='actor-north' AND status='revoked'",
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

/** Privileged, fixed-fixture statements ONLY on disposable GitHub PG16.
 * Only synthetic actor and SHA-256 hex IDs are interpolated, never bearer,
 * Core/production SQL or HTTP input. All runtime values are regex guarded. */
function tokenFixtureSql(sql) {
  const child = Bun.spawnSync(
    ['psql','-X','-q','-v','ON_ERROR_STOP=1','-c',sql],
    { stdout:'ignore', stderr:'ignore' }
  );
  assert.equal(child.exitCode,0,'Disposable token-bound fixture mutation failed');
}

/** Only the ephemeral privileged fixture can SET ROLE to one of two
 * dedicated NOLOGIN roles. No raw bearer/session secret is interpolated. */
function issuerFixtureBoolean(role, trustedCall) {
  assert.ok(['saas_issuer_provisioner','saas_issuer_directory_admin'].includes(role));
  assert.ok(typeof trustedCall === 'string' &&
    trustedCall.startsWith('saas_rls_private.'));
  const run = Bun.spawnSync(
    ['psql','-X','-t','-A','-q','-v','ON_ERROR_STOP=1','-c',
      'BEGIN; SET LOCAL ROLE '+role+'; SELECT '+trustedCall+'; COMMIT;'],
    { stderr:'ignore' }
  );
  assert.equal(run.exitCode,0,'Ephemeral issuer fixture SQL failed');
  const values = Buffer.from(run.stdout).toString('utf8')
    .split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  assert.ok(values.length>=1,'Missing issuer fixture result');
  const decisions = values.filter(x => x === 't' || x === 'f');
  assert.equal(decisions.length,1,'Malformed issuer fixture attestation');
  return decisions[0] === 't';
}

async function verifiedBearerFingerprint(bearer) {
  const bytes = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',new TextEncoder().encode(bearer)));
  const hex = Buffer.from(bytes).toString('hex');
  assert.match(hex,/^[0-9a-f]{64}$/);
  return hex;
}

/** Privileged fixture-only assertion: observe the committed audit event
 * from the actual non-superuser trusted publication, not mock SQL rows. */
function readLastCommittedNorthAuditId() {
  const run = Bun.spawnSync([
    'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',
    "SELECT COALESCE(MAX(event_id),0) FROM saas_rls_private.local_publication_audit_outbox WHERE tenant_id='demo-north'",
  ], { stderr:'ignore' });
  assert.equal(run.exitCode,0,'Private audit fixture unavailable');
  const value=Buffer.from(run.stdout).toString('utf8').trim();
  assert.match(value,/^[0-9]+$/);
  return Number(value);
}

/** No client-facing output: an isolated NOLOGIN PG role observes only an
 * already committed local audit ID. This is NOT remote HTTP delivery. */
/** Disposable PG fixture only. The role can claim/ACK *mock* event labels,
 * not transport a payload or claim real HTTP receipt. */
function syntheticDeliveryFixtureSql(eventId, sqlBuilder) {
  assert.ok(Number.isSafeInteger(eventId) && eventId > 0);
  const sql = sqlBuilder(eventId);
  assert.ok(typeof sql === 'string' &&
    sql.includes('saas_rls_private.') && sql.length < 1400);
  const run=Bun.spawnSync(
    ['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',sql],
    { stderr:'ignore' }
  );
  assert.equal(run.exitCode,0,'CI-only synthetic delivery SQL failed');
  return Buffer.from(run.stdout).toString('utf8').trim();
}

function mockDeliveryLease(eventId, seconds) {
  assert.ok([1,15].includes(seconds));
  const output=syntheticDeliveryFixtureSql(eventId,id =>
    'BEGIN; SET LOCAL ROLE saas_mock_delivery_worker; ' +
    'SELECT delivery_event_id::text || \'|\' || delivery_generation::text ' +
    '|| \'|\' || fencing_token::text || \'|\' || idempotency_key::text ' +
    '|| \'|\' || attempt_number::text ' +
    'FROM saas_rls_private.claim_synthetic_delivery(1,'+seconds+','+id+'); COMMIT;'
  );
  if (!output) return null;
  const parts=output.split('|');
  assert.equal(parts.length,5);
  assert.equal(parts[0],String(eventId));
  assert.match(parts[2],/^[0-9a-f-]{36}$/);
  assert.match(parts[3],/^[0-9a-f-]{36}$/);
  return Object.freeze({
    eventId, generation:Number(parts[1]), fencingToken:parts[2],
    idempotencyKey:parts[3], attempt:Number(parts[4]),
  });
}

function mockDeliveryAck(lease, idempotencyKey=lease.idempotencyKey) {
  assert.match(lease.fencingToken,/^[0-9a-f-]{36}$/);
  assert.match(idempotencyKey,/^[0-9a-f-]{36}$/);
  const result=syntheticDeliveryFixtureSql(lease.eventId,id =>
    'BEGIN; SET LOCAL ROLE saas_mock_delivery_worker; SELECT ' +
    'saas_rls_private.mark_mock_delivery_ack('+id+','+lease.generation+
    ',\''+lease.fencingToken+'\'::uuid,\''+idempotencyKey+'\'::uuid); COMMIT;'
  );
  assert.ok(result === 't' || result === 'f');
  return result === 't';
}

function reconcileCommittedLocalAuditInFixture(eventId) {
  assert.ok(Number.isSafeInteger(eventId) && eventId>0);
  const fixtureQuery=(sql)=>{
    const run=Bun.spawnSync([
      'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',sql,
    ], {stderr:'ignore'});
    assert.equal(run.exitCode,0,'Ephemeral reconciler SQL failed');
    return Buffer.from(run.stdout).toString('utf8').trim();
  };
  const claim=fixtureQuery(
    "BEGIN; SET LOCAL ROLE saas_audit_reconciler; SELECT event_id::text || '|' || generation::text || '|' || lease_token::text FROM saas_rls_private.claim_committed_local_audit(1,15,"+eventId+"); COMMIT;"
  );
  const values=claim.split('|');
  assert.equal(values.length,3);
  assert.equal(values[0],String(eventId));
  assert.equal(values[1],'1');
  assert.match(values[2],/^[0-9a-f-]{36}$/);
  const observed=fixtureQuery(
    "BEGIN; SET LOCAL ROLE saas_audit_reconciler; SELECT saas_rls_private.mark_local_audit_reconciled("+eventId+",1,'"+values[2]+"'::uuid); COMMIT;"
  );
  assert.equal(observed,'t','Only current private lease may finish local audit');
  assert.equal(fixtureQuery(
    "SELECT status FROM saas_rls_private.local_audit_reconciliation_state WHERE event_id="+eventId
  ),'reconciled_local');
  assert.equal(fixtureQuery(
    "SELECT COUNT(*) FROM saas_rls_private.local_audit_reconciliation_history WHERE event_id="+eventId
  ),'2');
}

function readPrivateOutboxCount() {
  const result = Bun.spawnSync(
    ['psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c',
      'SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox'],
    { stderr: 'ignore' }
  );
  assert.equal(result.exitCode, 0, 'Ephemeral private audit unavailable');
  const raw = Buffer.from(result.stdout).toString('utf8').trim();
  assert.match(raw, /^[0-9]+$/);
  return Number(raw);
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
  ['actor-token-ci', {
    id: 'actor-token-ci', memberships: [member('demo-north', 'tenant-viewer')],
  }],
  ['actor-issuer-ci', {
    id: 'actor-issuer-ci', memberships: [member('demo-north', 'tenant-viewer')],
  }],
]);
const directory = new Map([
  [issuer + ':sub-north', 'actor-north'],
  [issuer + ':sub-orbit', 'actor-orbit'],
  [issuer + ':sub-auditor', 'actor-auditor'],
  [issuer + ':sub-paused', 'actor-paused'],
  [issuer + ':sub-db-revoked', 'actor-db-revoked'],
  [issuer + ':sub-token-ci', 'actor-token-ci'],
  [issuer + ':sub-issuer-ci', 'actor-issuer-ci'],
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
    { change: 'revokeNorthSession', restore: 'restoreNorthSession',
      label: 'authoritative PG actor-wide session revoked after metadata COMMIT' },
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
  const outboxBefore = readPrivateOutboxCount();
  const lastNorthAuditBefore=readLastCommittedNorthAuditId();
  const publishRead = createTrustedSqlPublishedBoundary(
    { ...createTrustedDependencies(driver, audit,
      createSignedPgAuthorizationRevisionSource(driver, signer)),
      recordStagingOutbox: true },
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
  assert.equal(readPrivateOutboxCount(), outboxBefore + 1,
    'Signed audit outbox must persist only after successful COMMIT');
  const committedAuditId=readLastCommittedNorthAuditId();
  assert.ok(committedAuditId>lastNorthAuditBefore,
    'Signed trusted publication must create a NEW committed PG event');
  assert.equal(mockDeliveryLease(committedAuditId,1),null,
    'Commit-only synthetic intent must wait for LOCAL audit observation');
  reconcileCommittedLocalAuditInFixture(committedAuditId);
  // Pure memory receiver: one mock side effect keyed by the immutable
  // event UUID. First delivery succeeds at receiver but ACK is dropped.
  // Retry MUST carry same key and receiver MUST NOT apply effect twice.
  const mockReceiverEffects = new Map();
  const mockAccept = lease => {
    const found = mockReceiverEffects.get(lease.idempotencyKey);
    if (found !== undefined) {
      assert.equal(found,lease.eventId,'Mock receiver dedup may not cross events');
      return lease.idempotencyKey;
    }
    mockReceiverEffects.set(lease.idempotencyKey,lease.eventId);
    return lease.idempotencyKey;
  };
  const firstMockLease=mockDeliveryLease(committedAuditId,1);
  assert.equal(firstMockLease.generation,1);
  assert.equal(firstMockLease.attempt,1);
  const acceptedMockAck=mockAccept(firstMockLease);
  assert.equal(acceptedMockAck,firstMockLease.idempotencyKey);
  // Network-free simulation of lost acknowledgement: do not mark DB ACK.
  assert.equal(mockReceiverEffects.size,1);
  await Bun.sleep(1350);
  const retriedMockLease=mockDeliveryLease(committedAuditId,15);
  assert.equal(retriedMockLease.generation,2);
  assert.equal(retriedMockLease.attempt,2);
  assert.equal(retriedMockLease.idempotencyKey,firstMockLease.idempotencyKey);
  assert.notEqual(retriedMockLease.fencingToken,firstMockLease.fencingToken);
  assert.equal(mockAccept(retriedMockLease),acceptedMockAck,
    'Mock receiver must acknowledge duplicate immutable event idempotently');
  assert.equal(mockReceiverEffects.size,1,
    'Lost ACK must not produce second synthetic receiver effect');
  assert.equal(mockDeliveryAck(firstMockLease),false,
    'Old generation cannot falsely finish a reclaimed event');
  assert.equal(mockDeliveryAck(retriedMockLease,firstMockLease.fencingToken),false,
    'A guessed or incorrect mock ACK marker must be rejected');
  assert.equal(mockDeliveryAck(retriedMockLease),true,
    'Only current fenced claim with correct mock response may be marked');
  assert.equal(mockDeliveryAck(retriedMockLease),false,
    'Duplicate mock ACK must be terminal and harmless');
  assert.equal(mockDeliveryLease(committedAuditId,1),null,
    'Committed terminal mock event must never be redelivered');
  const terminalMockState=syntheticDeliveryFixtureSql(committedAuditId,id =>
    'SELECT status || \'|\' || attempts::text FROM ' +
    'saas_rls_private.synthetic_delivery_state WHERE event_id='+id
  );
  assert.equal(terminalMockState,'mock_acked|2');
  for (const secret of [firstMockLease.idempotencyKey,
    firstMockLease.fencingToken,retriedMockLease.fencingToken]) {
    assert.equal(JSON.stringify(publicationReceipt).includes(secret),false,
      'No worker key may enter a public receipt');
  }
  // Adversarial unfixable boundary: a synchronous LOCAL effect may happen
  // while an independently signed PG transaction is still uncommitted.
  // If PostgreSQL later ROLLBACKs, the event+intent vanish but the mock
  // recipient cannot be "un-called". This is a NEGATIVE proof and never a
  // valid remote-delivery/ACK contract. No external network is used here.
  const ambiguousEffects = [];
  const beforeAmbiguous = readPrivateOutboxCount();
  const ambiguousSql =
    "BEGIN; SET LOCAL statement_timeout='10000ms'; " +
    "SELECT saas_rls_test.issue_scope('actor-north','demo-north',120); " +
    "SET LOCAL ROLE saas_rls_reader; " +
    "SELECT saas_rls_test.assert_true(" +
    "saas_rls.record_signed_local_publication(" +
    "'demo-north','actor-north','tenant-admin','projects'," +
    "'ci-synthetic-orphan-precommit')," +
    "'Signed synthetic precommit Allow required'); " +
    "SELECT pg_sleep(2); RESET ROLE; ROLLBACK;";
  const ambiguousWorker=Bun.spawn({
    cmd:['psql','-X','-q','-v','ON_ERROR_STOP=1','-c',ambiguousSql],
    env:{...process.env,PGAPPNAME:'saas_mock_local_before_rollback'},
    stdout:'ignore',stderr:'ignore',
  });
  let sawUncommitted=false;
  try {
    for(let i=0;i<30;i+=1) {
      const check=Bun.spawnSync([
        'psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-c',
        "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_mock_local_before_rollback' AND wait_event='PgSleep'",
      ],{stderr:'ignore'});
      assert.equal(check.exitCode,0);
      if(Buffer.from(check.stdout).toString('utf8').trim()==='1') {
        sawUncommitted=true;
        break;
      }
      await Bun.sleep(45);
    }
    assert.equal(sawUncommitted,true,
      'Synthetic source must have staged signed event before local callback');
    ambiguousEffects.push('SYNTHETIC_LOCAL_EFFECT_ALREADY_EMITTED');
    assert.equal(ambiguousEffects.length,1);
    assert.equal(await ambiguousWorker.exited,0,
      'Explicit signed synthetic transaction must end with ROLLBACK');
  } finally {
    if(!sawUncommitted) ambiguousWorker.kill();
  }
  assert.equal(readPrivateOutboxCount(),beforeAmbiguous,
    'ROLLBACK removed audit+intent despite local effect already being emitted');
  const orphan=Bun.spawnSync([
    'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',
    "SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox e " +
    "LEFT JOIN saas_rls_private.synthetic_delivery_intents i ON i.event_id=e.event_id " +
    "WHERE e.correlation_id='ci-synthetic-orphan-precommit'",
  ],{stderr:'ignore'});
  assert.equal(orphan.exitCode,0);
  assert.equal(Buffer.from(orphan.stdout).toString('utf8').trim(),'0');
  assert.deepEqual(ambiguousEffects,['SYNTHETIC_LOCAL_EFFECT_ALREADY_EMITTED'],
    'No PostgreSQL audit can prove absence or reverse the uncommitted effect');
  console.info('PASS: synthetic pre-COMMIT local effect survives PG ROLLBACK while signed intent vanishes (negative proof)');
  assert.equal('eventId' in publicationReceipt,false);
  assert.equal('leaseToken' in publicationReceipt,false);
  assertAudit(publicationReceipt, {
    reason: 'read-allowed', actorId: 'actor-north', tenantId: 'demo-north',
  });
  const wrongTenantReceipt = await publishRead(
    request(north, 'demo-orbit', 'projects')
  );
  assert.equal(wrongTenantReceipt.status, 404);
  assert.equal('rows' in wrongTenantReceipt, false);
  assert.deepEqual(trustedPublished, ['north-project']);
  assert.equal(readPrivateOutboxCount(), outboxBefore + 1,
    'Cross-tenant refusal must not insert a fake Allow event');
  assert.equal(driver.stats().poisoned, false);
  console.info('PASS: real Bun.SQL commit→local audit→synthetic idempotent intent retry, lost MOCK ACK only');

  // Stage 2G.4d.7e: NEW opt-in intent-only publication mode. There is no
  // injected sync local handoff at all; only 009/013 writes may commit.
  // An independent worker follows the PG COMMIT and 012 reconciliation.
  const safeDependencies = {
    ...createTrustedDependencies(driver,audit,
      createSignedPgAuthorizationRevisionSource(driver,signer)),
    recordStagingOutbox:true,
  };
  assert.throws(
    () => createTrustedSyntheticCommittedIntentBoundary({
      ...safeDependencies,recordStagingOutbox:false,
    }),
    /Refusing post-COMMIT intent/,
    'Intent-only publication MUST require signed staging outbox'
  );
  const safeIntent = createTrustedSyntheticCommittedIntentBoundary(safeDependencies);
  const beforeSafeOutbox=readPrivateOutboxCount();
  const beforeSafeEvent=readLastCommittedNorthAuditId();
  const safeIntentReceipt=await safeIntent(
    request(north,'demo-north','projects',{limit:1})
  );
  assert.equal(safeIntentReceipt.ok,true);
  assert.equal(safeIntentReceipt.status,200);
  assert.equal(safeIntentReceipt.source,'staging-committed-intent-only');
  assert.equal(safeIntentReceipt.intentCommitted,true);
  assert.equal(safeIntentReceipt.externalReceipt,'not_attested');
  for(const forbidden of ['published','rows','tenantId','idempotencyKey',
    'leaseToken','delivery_event_id','north-project',north]) {
    assert.equal(JSON.stringify(safeIntentReceipt).includes(forbidden),false,
      'Intent receipt must not imply external handoff or leak payload/worker state');
  }
  assert.equal(readPrivateOutboxCount(),beforeSafeOutbox+1,
    'Intent must be durable only after signed SQL COMMIT');
  const safeEventId=readLastCommittedNorthAuditId();
  assert.ok(safeEventId>beforeSafeEvent);
  assert.equal(syntheticDeliveryFixtureSql(safeEventId,id =>
    'SELECT COUNT(*) FROM saas_rls_private.synthetic_receiver_effects WHERE event_id='+id),
  '0','No downstream LOCAL effect is allowed in a pre-COMMIT callback');
  assert.equal(mockDeliveryLease(safeEventId,1),null,
    'A committed event does not skip independently durable audit observation');
  const foreignSafeIntent=await safeIntent(
    request(north,'demo-orbit','projects',{limit:1})
  );
  assert.equal(foreignSafeIntent.ok,false);
  assert.equal(foreignSafeIntent.status,404);
  assert.equal(readPrivateOutboxCount(),beforeSafeOutbox+1,
    'Foreign tenant cannot create any durable post-commit intent');

  reconcileCommittedLocalAuditInFixture(safeEventId);
  const firstSafeLease=mockDeliveryLease(safeEventId,1);
  assert.equal(firstSafeLease.generation,1);
  assert.equal(firstSafeLease.attempt,1);
  const receiveDurably = (lease) => {
    assert.match(lease.idempotencyKey,/^[0-9a-f-]{36}$/);
    const outcome=syntheticDeliveryFixtureSql(lease.eventId,id =>
      'BEGIN; SET LOCAL ROLE saas_mock_receiver; SELECT '+
      "receiver_receipt::text || '|' || applied_now::text FROM "+
      'saas_rls_private.receive_synthetic_delivery('+id+",'"+
      lease.idempotencyKey+"'::uuid,'audit_observed_v1'); COMMIT;"
    );
    const values=outcome.split('|');
    assert.equal(values.length,2);
    assert.match(values[0],/^[0-9a-f-]{36}$/);
    assert.ok(values[1]==='true'||values[1]==='false');
    return {receipt:values[0],appliedNow:values[1]==='true'};
  };
  const markDurableReceipt=(lease,receipt)=>{
    assert.match(receipt,/^[0-9a-f-]{36}$/);
    const answer=syntheticDeliveryFixtureSql(lease.eventId,id =>
      'BEGIN; SET LOCAL ROLE saas_mock_delivery_worker; SELECT '+
      'saas_rls_private.mark_mock_receiver_ack('+id+','+
      lease.generation+",'"+lease.fencingToken+"'::uuid,'"+
      receipt+"'::uuid); COMMIT;"
    );
    assert.ok(answer==='t'||answer==='f');
    return answer==='t';
  };
  const receiverFirst=receiveDurably(firstSafeLease);
  assert.equal(receiverFirst.appliedNow,true);
  assert.equal(syntheticDeliveryFixtureSql(safeEventId,id =>
    'SELECT COUNT(*) FROM saas_rls_private.synthetic_receiver_effects WHERE event_id='+id),
  '1','Synthetic receiver effect and receipt are committed together');
  // Deliberate sender crash / lost acknowledgement. A new physical
  // receiver process will reopen PG; the effect must stay singleton.
  await Bun.sleep(1350);
  const secondSafeLease=mockDeliveryLease(safeEventId,15);
  assert.equal(secondSafeLease.generation,2);
  assert.equal(secondSafeLease.attempt,2);
  assert.equal(secondSafeLease.idempotencyKey,firstSafeLease.idempotencyKey);
  assert.notEqual(secondSafeLease.fencingToken,firstSafeLease.fencingToken);
  const receiverReplay=receiveDurably(secondSafeLease);
  assert.equal(receiverReplay.appliedNow,false);
  assert.equal(receiverReplay.receipt,receiverFirst.receipt);
  assert.equal(markDurableReceipt(firstSafeLease,receiverFirst.receipt),false,
    'Stale sender fence can never authorize a newly claimed ACK');
  assert.equal(markDurableReceipt(secondSafeLease,crypto.randomUUID()),false,
    'Guessed receipt is insufficient for positive ACK');
  assert.equal(markDurableReceipt(secondSafeLease,receiverReplay.receipt),true);
  assert.equal(markDurableReceipt(secondSafeLease,receiverReplay.receipt),false);
  assert.equal(syntheticDeliveryFixtureSql(safeEventId,id =>
    "SELECT status || '|' || attempts::text FROM "+
    'saas_rls_private.synthetic_delivery_state WHERE event_id='+id),
  'mock_acked|2');
  assert.equal(syntheticDeliveryFixtureSql(safeEventId,id =>
    'SELECT COUNT(*) FROM saas_rls_private.synthetic_receiver_effects WHERE event_id='+id),
  '1','Lost ACK plus retry must not cause a second receiver-local effect');
  console.info('PASS: event-only trusted post-COMMIT intent -> durable PG receiver -> lost ACK -> fenced retry');

  // Fail the exact signed publication COMMIT by executing ROLLBACK on its
  // REAL reserved PostgreSQL connection before COMMIT reaches the server.
  // No receipt/effect can have been emitted by the new no-op-only handoff.
  const failingSql=nativeSql(1);
  const failingBase=boundedDriver(failingSql);
  let hadStagedOutbox=false;
  let forcedRollback=false;
  const failCommitPool={
    quarantine(reason){ failingBase.quarantine(reason); },
    async connect(signal){
      const reserved=await failingBase.connect(signal);
      return {
        release(discard){return reserved.release(discard);},
        async query(statement,params,querySignal){
          if(statement===SCOPED_PUBLICATION_OUTBOX_SQL){
            const result=await reserved.query(statement,params,querySignal);
            if(result.rows?.[0]?.recorded===true) hadStagedOutbox=true;
            return result;
          }
          if(statement==='COMMIT' && hadStagedOutbox){
            forcedRollback=true;
            await reserved.query('ROLLBACK',[],querySignal);
            throw new Error('CI-only forced rollback before outbox COMMIT');
          }
          return reserved.query(statement,params,querySignal);
        },
      };
    },
  };
  const beforeFailedOutbox=readPrivateOutboxCount();
  try {
    const interruptedIntent=createTrustedSyntheticCommittedIntentBoundary({
      ...createTrustedDependencies(failCommitPool,audit,
        createSignedPgAuthorizationRevisionSource(failCommitPool,signer)),
      recordStagingOutbox:true,
    });
    const failed=await interruptedIntent(
      request(north,'demo-north','projects',{limit:1})
    );
    assert.equal(hadStagedOutbox,true,
      'Failure must actually occur after signed audit + intent insertion');
    assert.equal(forcedRollback,true,
      'Fault injection must intercept only the publication transaction COMMIT');
    assert.equal(failed.ok,false);
    assert.equal(failed.status,503);
    assert.equal('intentCommitted' in failed,false);
    assert.equal(readPrivateOutboxCount(),beforeFailedOutbox,
      'Forced SQL rollback must leave zero new committed intents');
  } finally {
    if(!failingBase.stats().poisoned) await failingSql.close({timeout:0});
  }
  console.info('PASS: injected pre-COMMIT ROLLBACK keeps synthetic receiver unreachable without emitting local effect');

  // Opposite uncertainty: PostgreSQL COMMIT SUCCEEDS but its reply is
  // artificially lost. No caller-facing success is permitted; an independent
  // synthetic worker can recover the persisted intent without resubmitting
  // the request and thereby creating another logical event.
  const uncertainSql=nativeSql(1);
  const uncertainBase=boundedDriver(uncertainSql);
  let uncertainStaged=false;
  let committedReplyLost=false;
  const lostReplyPool={
    quarantine(reason){ uncertainBase.quarantine(reason); },
    async connect(signal){
      const reserved=await uncertainBase.connect(signal);
      return {
        release(discard){return reserved.release(discard);},
        async query(statement,params,querySignal){
          if(statement===SCOPED_PUBLICATION_OUTBOX_SQL){
            const result=await reserved.query(statement,params,querySignal);
            if(result.rows?.[0]?.recorded===true) uncertainStaged=true;
            return result;
          }
          if(statement==='COMMIT' && uncertainStaged){
            await reserved.query('COMMIT',[],querySignal);
            committedReplyLost=true;
            throw new Error('CI-only unknown COMMIT reply after real PostgreSQL commit');
          }
          return reserved.query(statement,params,querySignal);
        },
      };
    },
  };
  const beforeUnknown=readPrivateOutboxCount();
  const previousUnknownEvent=readLastCommittedNorthAuditId();
  try {
    const uncertainBoundary=createTrustedSyntheticCommittedIntentBoundary({
      ...createTrustedDependencies(lostReplyPool,audit,
        createSignedPgAuthorizationRevisionSource(lostReplyPool,signer)),
      recordStagingOutbox:true,
    });
    const unknown=await uncertainBoundary(
      request(north,'demo-north','projects',{limit:1})
    );
    assert.equal(uncertainStaged,true);
    assert.equal(committedReplyLost,true,
      'The injected error MUST happen strictly after real PostgreSQL COMMIT');
    assert.equal(unknown.ok,false);
    assert.equal(unknown.status,503);
    assert.equal('intentCommitted' in unknown,false,
      'A lost COMMIT reply cannot be returned as an attested success');
    assert.equal(readPrivateOutboxCount(),beforeUnknown+1,
      'Committed event is durable even when sender did not receive a success');
  } finally {
    if(!uncertainBase.stats().poisoned) await uncertainSql.close({timeout:0});
  }
  const survivedId=readLastCommittedNorthAuditId();
  assert.ok(survivedId>previousUnknownEvent);
  assert.equal(syntheticDeliveryFixtureSql(survivedId,id =>
    'SELECT COUNT(*) FROM saas_rls_private.synthetic_receiver_effects WHERE event_id='+id),
  '0','Commit-response uncertainty must not accidentally send before worker claim');
  reconcileCommittedLocalAuditInFixture(survivedId);
  const recoveredLease=mockDeliveryLease(survivedId,15);
  assert.ok(recoveredLease);
  const recoveredEffect=receiveDurably(recoveredLease);
  assert.equal(recoveredEffect.appliedNow,true);
  assert.equal(markDurableReceipt(recoveredLease,recoveredEffect.receipt),true);
  assert.equal(syntheticDeliveryFixtureSql(survivedId,id =>
    'SELECT COUNT(*) FROM saas_rls_private.synthetic_receiver_effects WHERE event_id='+id),
  '1');
  console.info('PASS: real COMMIT with lost reply yields 503/UNKNOWN, yet independent PG worker recovers single durable intent');


  // 2G.4d.7a: real ephemeral PostgreSQL with TWO verified RS256 bearer
  // tokens for the SAME actor. The server derives SHA-256 of each exact
  // token; client-provided jti is never trusted as a SQL scope/session ID.
  // Enrollment and revocation are privileged CI fixture operations only.
  const boundA = await token('sub-token-ci',{jti:'ci-separate-a'});
  const boundB = await token('sub-token-ci',{jti:'ci-separate-b'});
  const fpA = await verifiedBearerFingerprint(boundA);
  const fpB = await verifiedBearerFingerprint(boundB);
  assert.notEqual(fpA,fpB);
  let boundRegistered = false;
  const handoffs = [];
  const boundOutboxBefore = readPrivateOutboxCount();
  try {
    tokenFixtureSql(`BEGIN;
      INSERT INTO saas_rls.memberships(actor_id,tenant_id,role,status)
      VALUES ('actor-token-ci','demo-north','tenant-viewer','active');
      INSERT INTO saas_rls_private.actor_session_state(actor_id,status)
      VALUES ('actor-token-ci','active');
      INSERT INTO saas_rls_private.actor_token_sessions
        (fingerprint,actor_id,status,expires_at)
      VALUES ('${fpA}','actor-token-ci','active',clock_timestamp()+interval '85 seconds'),
             ('${fpB}','actor-token-ci','active',clock_timestamp()+interval '85 seconds');
      COMMIT;`);
    boundRegistered = true;
    const revisionAtEnrollment = readEphemeralNorthEpoch();
    const boundPublisher = createTrustedSqlPublishedBoundary(
      { ...createTrustedDependencies(driver,audit,
        createSignedPgAuthorizationRevisionSource(driver,signer)),
        requireTokenBoundSession:true, recordStagingOutbox:true },
      {
        async stage(payload,signal) {
          assert.equal(signal.aborted,false);
          assert.equal(payload.tenantId,'demo-north');
          assert.deepEqual(payload.rows.map(r=>r.id),['north-project']);
          assert.equal(JSON.stringify(payload).includes('bearer'),false);
          return () => { handoffs.push('north-project'); };
        },
      }
    );
    const readBound = (bearer) => boundPublisher(
      request(bearer,'demo-north','projects',{limit:1})
    );
    const allowedA = await readBound(boundA);
    const allowedB = await readBound(boundB);
    for (const receipt of [allowedA,allowedB]) {
      assert.equal(receipt.ok,true);
      assert.equal(receipt.published,true);
      assert.equal('rows' in receipt,false);
      assert.equal('tenantId' in receipt,false);
      assert.equal(JSON.stringify(receipt).includes('token-ci'),false);
    }
    assert.deepEqual(handoffs,['north-project','north-project']);
    assert.equal(readPrivateOutboxCount(),boundOutboxBefore+2,
      'Both distinct signed tokens must append only minimal authorized records');

    // Even when token B is ACTIVE, actor-only signed SQL is now a deny.
    const attemptedDowngrade = await createRead(driver,audit,
      createSignedPgAuthorizationRevisionSource(driver,signer))(
        request(boundB,'demo-north','projects')
      );
    assert.equal(attemptedDowngrade.status,404);
    assert.equal('rows' in attemptedDowngrade,false);

    // One committed token-specific revoke advances the SAME private tenant
    // epoch, while the other token, membership, and actor stay active.
    tokenFixtureSql(`UPDATE saas_rls_private.actor_token_sessions
      SET status='revoked' WHERE fingerprint='${fpA}' AND status='active'`);
    assert.equal(BigInt(readEphemeralNorthEpoch()),BigInt(revisionAtEnrollment)+1n,
      'Token A revocation must increment North tenant epoch exactly once');
    const revokedA = await readBound(boundA);
    assert.equal(revokedA.ok,false);
    assert.equal(revokedA.status,404);
    assert.equal('rows' in revokedA,false);
    assert.deepEqual(handoffs,['north-project','north-project'],
      'Revoked token must never perform another handoff');
    assert.equal(readPrivateOutboxCount(),boundOutboxBefore+2,
      'Revoked token must not append misleading successful audit records');

    const stillB = await readBound(boundB);
    assert.equal(stillB.ok,true);
    assert.equal(stillB.published,true);
    assert.deepEqual(handoffs,Array(3).fill('north-project'));
    assert.equal(readPrivateOutboxCount(),boundOutboxBefore+3);
    assert.equal(driver.stats().poisoned,false);
  } finally {
    if (boundRegistered) {
      // Full fixture cleanup (a fresh ephemeral test database anyway).
      tokenFixtureSql(`BEGIN;
        DELETE FROM saas_rls_private.actor_token_sessions
          WHERE actor_id='actor-token-ci';
        DELETE FROM saas_rls_private.actor_session_state
          WHERE actor_id='actor-token-ci';
        DELETE FROM saas_rls.memberships WHERE actor_id='actor-token-ci';
        COMMIT;`);
    }
  }
  console.info('PASS: real PG16 token A revoked; sibling B remains allowed; legacy downgrade denied');

  // Stage 2G.4d.7b: actual pinned-RS256 server provisioning module sends
  // only the digest/verified exp to a STRICTLY separate NOLOGIN provisioner,
  // after a different issuer-directory-admin role pins issuer+subject->actor.
  const pinnedActor = 'actor-issuer-ci';
  const pinnedSubject = 'sub-issuer-ci';
  const issuerA = await token(pinnedSubject,{jti:'issuer-bound-A'});
  const issuerB = await token(pinnedSubject,{jti:'issuer-bound-B'});
  const issuerFingerprintA = await verifiedBearerFingerprint(issuerA);
  const issuerFingerprintB = await verifiedBearerFingerprint(issuerB);
  const issuerPublished = [];
  const outboxBeforeIssuer = readPrivateOutboxCount();
  let issuerActorRegistered = false;
  try {
    tokenFixtureSql(`BEGIN;
      INSERT INTO saas_rls.memberships(actor_id,tenant_id,role,status)
       VALUES ('actor-issuer-ci','demo-north','tenant-viewer','active');
      INSERT INTO saas_rls_private.actor_session_state(actor_id,status)
       VALUES ('actor-issuer-ci','active');
      COMMIT;`);
    issuerActorRegistered = true;

    const pinned = issuerFixtureBoolean('saas_issuer_directory_admin',
      "saas_rls_private.pin_verified_subject('"+
      issuer+"','"+pinnedSubject+"','"+pinnedActor+"')");
    assert.equal(pinned,true,'Only directory-admin pins subject ownership');

    const provisioner = createTrustedIssuerSessionProvisioner({
      tokens:verifier,
      actorDirectory:{
        async resolveActorId(id) {
          return directory.get(id.issuer + ':' + id.subject) ?? null;
        },
      },
      nowSeconds:()=>Math.floor(Date.now()/1000),
      writer:{
        async enrollVerifiedToken(v) {
          assert.equal(v.issuer,issuer,'Pinned issuer must be exact');
          assert.equal(v.subject,pinnedSubject,'No unpinned subject');
          assert.equal(v.actorId,pinnedActor,'Actor comes from server directory');
          assert.match(v.fingerprint,/^[0-9a-f]{64}$/);
          assert.ok(Number.isSafeInteger(v.expiresAtSeconds));
          return issuerFixtureBoolean('saas_issuer_provisioner',
            "saas_rls_private.enroll_verified_token('"+issuer+
            "','"+pinnedSubject+"','"+pinnedActor+"','"+v.fingerprint+
            "',to_timestamp("+v.expiresAtSeconds+"))");
        },
        async revokeVerifiedToken(v) {
          assert.equal(v.issuer,issuer);
          assert.equal(v.subject,pinnedSubject);
          assert.equal(v.actorId,pinnedActor);
          assert.match(v.fingerprint,/^[0-9a-f]{64}$/);
          return issuerFixtureBoolean('saas_issuer_provisioner',
            "saas_rls_private.revoke_verified_token('"+issuer+
            "','"+pinnedSubject+"','"+v.fingerprint+"')");
        },
      },
    });
    assert.equal(await provisioner.enrollBearer(
      await token(pinnedSubject,{aud:'wrong-audience'})),false,
      'Unverified bearer must not reach issuer-provisioner SQL');
    assert.equal(await provisioner.enrollBearer(issuerA),true);
    assert.equal(await provisioner.enrollBearer(issuerB),true);
    assert.equal(await provisioner.enrollBearer(issuerA),false,
      'Duplicate verified token cannot be re-enrolled or expiry-extended');

    const safePublisher = createTrustedSqlPublishedBoundary(
      { ...createTrustedDependencies(driver,audit,
        createSignedPgAuthorizationRevisionSource(driver,signer)),
        requireTokenBoundSession:true,recordStagingOutbox:true },
      {
        async stage(payload,signal) {
          assert.equal(signal.aborted,false);
          assert.equal(payload.tenantId,'demo-north');
          assert.deepEqual(payload.rows.map(r=>r.id),['north-project']);
          const serialized = JSON.stringify(payload);
          for(const banned of [
            issuerA,issuerB,issuerFingerprintA,issuerFingerprintB,pinnedSubject,
          ]) assert.equal(serialized.includes(banned),false);
          return ()=>{issuerPublished.push('north-project');};
        },
      }
    );
    const invoke = bearer => safePublisher(
      request(bearer,'demo-north','projects',{limit:1})
    );
    for(const bearer of [issuerA,issuerB]) {
      const receipt = await invoke(bearer);
      assert.equal(receipt.ok,true);
      assert.equal(receipt.published,true);
      assert.equal('rows' in receipt,false);
      assert.equal('tenantId' in receipt,false);
      const serialized=JSON.stringify(receipt);
      for (const banned of [
        issuerA,issuerB,issuerFingerprintA,issuerFingerprintB,pinnedSubject,
      ]) assert.equal(serialized.includes(banned),false);
    }
    assert.deepEqual(issuerPublished,['north-project','north-project']);
    assert.equal(readPrivateOutboxCount(),outboxBeforeIssuer+2);

    assert.equal(await provisioner.revokeBearer(issuerA),true);
    assert.equal(await provisioner.revokeBearer(issuerA),false);
    const deniedA=await invoke(issuerA);
    assert.equal(deniedA.ok,false);
    assert.equal(deniedA.status,404);
    assert.equal('rows' in deniedA,false);
    assert.equal(readPrivateOutboxCount(),outboxBeforeIssuer+2);
    assert.equal((await invoke(issuerB)).ok,true,
      'Subject remains active and independent token B remains usable');
    assert.equal(readPrivateOutboxCount(),outboxBeforeIssuer+3);

    // Revoking issuer+subject invalidates B despite its individual
    // fingerprint row remaining active: no per-token sweep is required.
    assert.equal(issuerFixtureBoolean('saas_issuer_directory_admin',
      "saas_rls_private.revoke_verified_subject('"+
      issuer+"','"+pinnedSubject+"')"),true);
    const deniedSubject=await invoke(issuerB);
    assert.equal(deniedSubject.ok,false);
    assert.equal(deniedSubject.status,404);
    assert.equal('rows' in deniedSubject,false);
    assert.equal(readPrivateOutboxCount(),outboxBeforeIssuer+3,
      'Revoked subject must never write success outbox');
    assert.deepEqual(issuerPublished,
      ['north-project','north-project','north-project']);
    assert.equal(driver.stats().poisoned,false);
  } finally {
    if (issuerActorRegistered) {
      // Identity binding/tombstones intentionally survive cleanup.
      tokenFixtureSql(`BEGIN;
        DELETE FROM saas_rls_private.actor_token_sessions
         WHERE actor_id='actor-issuer-ci';
        DELETE FROM saas_rls_private.actor_session_state
         WHERE actor_id='actor-issuer-ci';
        DELETE FROM saas_rls.memberships
         WHERE actor_id='actor-issuer-ci';
        COMMIT;`);
    }
  }
  console.info('PASS: real PG16 pinned issuer enroll/revoke: token A denied, B survives, subject revoke denies all');

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
