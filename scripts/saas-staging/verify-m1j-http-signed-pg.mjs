/**
 * M1j: REAL loopback HTTP -> synthetic pinned RS256 -> server-side actor
 * -> fsynced Ed25519 PRE-COMMIT attempt -> signed Bun.SQL PG16 transaction
 * -> M1d authorization fence, M1c audit and M1g UUID binding.
 *
 * GitHub disposable PostgreSQL16 ONLY. The HTTP factory remains unmounted
 * in production; no independent off-host WORM, OIDC, retry or exactly-once.
 */
import { createM1ProjectHttpHandler } from
  '../../src/features/saasBlueprint/controlApi/server/m1ProjectHttpHandler.ts';
import { startWitness, runOffline } from './verify-m1h-precommit-intent.mjs';

const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SAFE_PROJECT = /^m1j-[a-z-]{1,48}$/;

function fixtureSql(assert, query) {
  const result = Bun.spawnSync([
    'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', query,
  ], { stdout: 'pipe', stderr: 'pipe' });
  assert.equal(result.exitCode, 0, 'M1j disposable PG fixture query failed');
  return new TextDecoder().decode(result.stdout).trim();
}

function pgCounts(assert, projectId, attemptId) {
  assert.ok(SAFE_PROJECT.test(projectId));
  assert.ok(V4.test(attemptId));
  // Both interpolated values are constrained fixed-format test scalars.
  return fixtureSql(assert,
    "SELECT (SELECT COUNT(*) FROM saas_m1_private.projects WHERE " +
    "tenant_id='demo-north' AND project_id='" + projectId + "')::TEXT || ':' || " +
    "(SELECT COUNT(*) FROM saas_m1_private.project_write_audit_outbox WHERE " +
    "tenant_id='demo-north' AND project_id='" + projectId + "')::TEXT || ':' || " +
    "(SELECT COUNT(*) FROM saas_m1_private.project_attempt_bindings b " +
    "JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id " +
    "WHERE a.tenant_id='demo-north' AND a.project_id='" + projectId + "' " +
    "AND b.attempt_id='" + attemptId + "'::uuid)::TEXT"
  );
}

function setDbMembership(assert, state) {
  const commands = {
    revoke: "UPDATE saas_rls.memberships SET status='revoked' " +
      "WHERE actor_id='actor-north' AND tenant_id='demo-north' AND status='active'",
    restore: "UPDATE saas_rls.memberships SET status='active' " +
      "WHERE actor_id='actor-north' AND tenant_id='demo-north' AND status='revoked'",
  };
  assert.ok(Object.hasOwn(commands, state), 'M1j fixture only');
  assert.equal(fixtureSql(assert, commands[state]), 'UPDATE 1');
}

export async function verifyM1j({
  assert, makeDriver, verifier, directory, actors, signToken, northScope,
}) {
  if (process.env.GITHUB_ACTIONS !== 'true' ||
      process.env.SAAS_EPHEMERAL_M1_PG_CI !== 'true' ||
      process.env.SAAS_EPHEMERAL_M1G_ATTEMPT_CI !== 'true' ||
      process.env.SAAS_EPHEMERAL_M1_HTTP_CI !== 'true' ||
      process.env.SAAS_EPHEMERAL_M1J_HTTP_PG_CI !== 'true' ||
      process.env.SAAS_EPHEMERAL_M1H_INTENT_CI === 'true' ||
      process.env.PGHOST !== '127.0.0.1' ||
      process.env.PGPORT !== '5432' ||
      process.env.PGDATABASE !== 'saas_ephemeral_test' ||
      process.env.NODE_ENV === 'production' ||
      process.env.RAILWAY_PROJECT_ID ||
      process.env.RAILWAY_ENVIRONMENT ||
      process.env.RAILWAY_SERVICE_ID) {
    throw new Error('M1j requires separate disposable GitHub PG16 and HTTP CI flags');
  }

  console.info('STEP M1j: real loopback HTTP -> signed PG16 -> fsynced intent');
  const suffix = crypto.randomUUID();
  // Reuse M1h's STRICT local file-name whitelist and NO-PG signer process.
  const intentPath = '/tmp/saas-m1h-intent-' + suffix + '.jsonl';
  const witness = await startWitness(assert, intentPath);
  const issued = [];
  const native = [];
  let activeDriver = makeDriver({ attemptTagging: true });
  native.push(activeDriver);

  // This wrapper is injected only after M1i HTTP + M1a token/RBAC checks.
  // Client JSON/claims/headers NEVER supply attempt ID, actor or signer.
  const writer = Object.freeze({
    async execute(input) {
      const attemptId = crypto.randomUUID();
      const entry = {
        attemptId,
        actorId: input.scope.actorId,
        tenantId: input.scope.tenantId,
        projectId: input.projectId,
        operation: input.operation,
        expectedVersion: input.expectedVersion ?? null,
      };
      const receipt = await witness.prepare(entry);
      assert.equal(receipt.attemptId, attemptId);
      assert.equal(receipt.sequence, issued.length + 1);
      issued.push(entry);
      // Receipt is not emitted until the M1h signer fsynced the journal.
      return activeDriver.execute({ ...input, attemptId });
    },
  });
  const handler = createM1ProjectHttpHandler({
    tokens: verifier, directory, actors, writer,
    newCorrelationId: () => 'm1j-server-generated-correlation',
  }, { enabledForDisposableCi: true });
  const server = Bun.serve({
    hostname: '127.0.0.1', port: 0, fetch: handler,
  });
  let membershipRevoked = false;
  const origin = 'http://127.0.0.1:' + server.port;
  const projectPath = project =>
    '/control-api/v1/tenants/demo-north/metadata/projects/' + project;
  async function send(method, project, bearer, body, headers = {}) {
    const response = await fetch(origin + projectPath(project), {
      method, headers: {
        Authorization: 'Bearer ' + bearer,
        'Content-Type': 'application/json',
        ...headers,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(12000),
    });
    assert.equal(response.headers.get('Access-Control-Allow-Origin'), null);
    assert.equal(response.headers.get('Set-Cookie'), null);
    assert.ok(response.headers.get('Cache-Control')?.includes('no-store'));
    const data = await response.json();
    const serialized = JSON.stringify(data);
    assert.ok(!serialized.includes(bearer), 'M1j cannot leak bearer');
    assert.ok(!serialized.includes('PG_SECRET'), 'M1j cannot leak database diagnostics');
    assert.equal(response.headers.get('X-Correlation-Id'),
      'm1j-server-generated-correlation');
    return { status: response.status, data };
  }
  function replaceDriver(options) {
    const d = makeDriver(options);
    activeDriver = d;
    native.push(d);
    return d;
  }
  try {
    const north = await signToken('north', {
      role: 'tenant-owner', actorId: 'actor-orbit',
      tenantId: 'demo-orbit', attemptId: 'FORGED_CLIENT_ATTEMPT',
    });
    const viewer = await signToken('orbit', { role: 'tenant-owner' });
    const badAudience = await signToken('north', { aud: 'm1j-wrong-audience' });
    const auditor = await signToken('auditor');
    assert.equal((await send('POST','m1j-auth-denied',badAudience,
      { name: 'Denied' })).status, 401);
    assert.equal((await send('POST','m1j-auth-denied',auditor,
      { name: 'Denied' })).status, 404);
    assert.equal((await send('POST','m1j-auth-denied',viewer,
      { name: 'Denied' })).status, 404);
    assert.equal((await send('POST','m1j-auth-denied',north,
      { name: 'Denied' }, { 'X-Actor-Id': 'actor-orbit' })).status, 404);
    assert.equal((await send('POST','m1j-auth-denied',north,
      { name: 'Denied' }, { 'Idempotency-Key': crypto.randomUUID() })).status, 404);
    assert.equal((await send('POST','m1j-auth-denied',north,
      { name: 'Denied', actorId: 'actor-north' })).status, 404);
    assert.equal(issued.length, 0);
    assert.equal(activeDriver.stats().reservations, 0);

    // Real HTTP -> signed PG16 create/rename/soft-disable.
    assert.equal((await send('POST','m1j-flow',north,
      { name: 'M1j synthetic create' })).status, 201);
    assert.equal((await send('PATCH','m1j-flow',north,
      { name: 'M1j synthetic rename', expectedVersion: 1 })).status, 200);
    assert.equal((await send('DELETE','m1j-flow',north,
      { expectedVersion: 2 })).status, 200);
    assert.equal(issued.length, 3);
    assert.deepEqual(issued.map(x => x.operation), ['create','rename','disable']);
    assert.ok(issued.every(x => x.actorId === 'actor-north' &&
      x.tenantId === 'demo-north' && V4.test(x.attemptId)));
    assert.equal(activeDriver.stats().reservations, 3);
    assert.equal(activeDriver.stats().commitAcks, 3);
    assert.equal(activeDriver.stats().poisoned, false);

    const normal = activeDriver;
    const read = await normal.read(northScope, 'm1j-flow');
    assert.equal(read.length, 1);
    assert.equal(read[0].status, 'disabled');
    assert.equal(read[0].version, '3');
    // CAS and terminal lifecycle deny. The intent still exists, but no
    // project/audit/attempt binding should be added for a denied write.
    assert.equal((await send('PATCH','m1j-flow',north,
      { name: 'Must remain disabled', expectedVersion: 3 })).status, 404);
    assert.equal(issued.length, 4);
    assert.equal(pgCounts(assert, 'm1j-flow', issued[0].attemptId), '1:3:1');
    assert.equal(fixtureSql(assert,
      "SELECT COUNT(*) FROM saas_m1_private.project_attempt_bindings b " +
      "JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id " +
      "WHERE a.tenant_id='demo-north' AND a.project_id='m1j-flow'"), '3');
    assert.equal(pgCounts(assert, 'm1j-flow', issued[3].attemptId), '1:3:0');

    // The TypeScript membership view may be stale; a real signed PG16
    // transaction must independently refuse current database revocation.
    try {
      setDbMembership(assert, 'revoke');
      membershipRevoked = true;
      assert.equal((await send('POST','m1j-db-revoked',north,
        { name: 'Denied in database' })).status, 404);
      assert.equal(issued.length, 5);
      assert.equal(pgCounts(assert, 'm1j-db-revoked', issued[4].attemptId), '0:0:0');
    } finally {
      if (membershipRevoked) {
        setDbMembership(assert, 'restore');
        membershipRevoked = false;
      }
    }

    // Case A: real COMMIT succeeds, client ACK disappears. HTTP must
    // return generic 503, while project+audit+attempt are all durable
    // in this one PostgreSQL transaction. No retry or second reservation.
    const lostAck = replaceDriver({
      attemptTagging: true, dropAckAfterCommit: true,
    });
    const ackResponse = await send('POST','m1j-ack-lost',north,
      { name: 'Committed but 503' });
    assert.equal(ackResponse.status, 503);
    assert.deepEqual(lostAck.stats(), {
      poisoned: true, reservations: 1, commitAcks: 0,
    });
    assert.equal(issued.length, 6);
    assert.equal(pgCounts(assert, 'm1j-ack-lost', issued[5].attemptId), '1:1:1');

    // Case B: a second privileged disposable PG fixture kills the
    // *reserved* physical backend after project+audit INSERT but before
    // COMMIT. The witness remains signed, PostgreSQL rolls back 0/0/0.
    let lostPid = null;
    const disconnected = replaceDriver({
      attemptTagging: true,
      beforeCommit({ backendPid }) {
        assert.ok(Number.isSafeInteger(backendPid) && backendPid > 0);
        lostPid = backendPid;
        assert.equal(fixtureSql(assert,
          "SELECT CASE WHEN pg_terminate_backend(" + backendPid + ") " +
          "THEN 'terminated' ELSE 'missing' END"), 'terminated');
      },
    });
    assert.equal((await send('POST','m1j-precommit-loss',north,
      { name: 'Must rollback' })).status, 503);
    assert.deepEqual(disconnected.stats(), {
      poisoned: true, reservations: 1, commitAcks: 0,
    });
    assert.ok(lostPid && lostPid>0);
    assert.equal(fixtureSql(assert,
      'SELECT COUNT(*) FROM pg_stat_activity WHERE pid='+lostPid), '0');
    assert.equal(issued.length, 7);
    assert.equal(pgCounts(assert,'m1j-precommit-loss',issued[6].attemptId),'0:0:0');

    // One signed precommit intent for each authorized *attempt*, not for
    // a forged HTTP request or a guaranteed COMMIT. The local signer is
    // a second process without PostgreSQL credentials; not off-host WORM.
    await witness.stop();
    const verified = runOffline(assert, intentPath, witness.publicKey, 7);
    assert.ok(verified && verified.count===7);
    assert.deepEqual(verified.attempts, issued);
    assert.ok(verified.attempts.every(x => V4.test(x.attemptId)));

    // Signer unavailable => HTTP 503 BEFORE reserving ANY PG session.
    const signerDead = replaceDriver({ attemptTagging: true });
    assert.equal((await send('POST','m1j-signer-dead',north,
      { name: 'Do not reserve PG' })).status, 503);
    assert.equal(signerDead.stats().reservations, 0);
    assert.equal(issued.length, 7);
    assert.equal(fixtureSql(assert,
      "SELECT (SELECT COUNT(*) FROM saas_m1_private.projects " +
      "WHERE project_id='m1j-signer-dead')::TEXT || ':' || " +
      "(SELECT COUNT(*) FROM saas_m1_private.project_write_audit_outbox " +
      "WHERE project_id='m1j-signer-dead')::TEXT"), '0:0');
    console.info(
      'PASS M1j: real loopback POST/PATCH/DELETE -> pinned RS256 tenant RBAC ' +
      '-> fsynced Ed25519 intent -> signed PG16 M1d fence/M1c audit/M1g UUID; ' +
      'revoked DB denies, committed lost ACK=503 1/1/1, killed backend=503 ' +
      '0/0/0, stopped signer prevents PG reservation; NO retry/production/WORM'
    );
  } finally {
    if (membershipRevoked) setDbMembership(assert, 'restore');
    server.stop(true);
    await witness.stop();
    await Promise.all(native.map(d => d.close()));
  }
}
