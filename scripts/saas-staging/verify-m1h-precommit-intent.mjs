/**
 * M1h: two real PG16 write outcomes preceded by separately fsynced, signed
 * ephemeral intent. NO production code, network signer or automatic retry.
 * Executed only by the existing isolated Bun E2E with M1g SQL024 installed.
 */
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFile, writeFile } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';

const WORKER = 'scripts/saas-staging/m1h-precommit-intent-journal.mjs';
const utf8 = bytes => new TextDecoder().decode(bytes).trim();
const witnessEnv = Object.freeze({
  PATH: process.env.PATH || '/usr/bin:/bin',
  GITHUB_ACTIONS: 'true',
  SAAS_EPHEMERAL_M1H_INTENT_CI: 'true',
  PGHOST: '127.0.0.1',
  PGPORT: '5432',
  PGDATABASE: 'saas_ephemeral_test',
});
// Deliberately excludes PGUSER/PGPASSWORD, SQL scope signing keys,
// Railway credentials, project name, JWT, auths and other env secrets.
const validV4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function realPgFixture(assert, statement) {
  const result = Bun.spawnSync(
    ['psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', statement],
    { stdout: 'pipe', stderr: 'pipe' }
  );
  assert.equal(result.exitCode, 0, 'M1h isolated postgres fixture failed');
  return utf8(result.stdout);
}

export async function startWitness(assert, file) {
  const child = spawn('node', [WORKER, 'writer', file], {
    env: witnessEnv, stdio: ['pipe', 'pipe', 'ignore'],
  });
  let alive = true;
  let publicKey = null;
  let waiting = null;
  let signalReady;
  let failReady;
  const ready = new Promise((resolve, reject) => {
    signalReady = resolve; failReady = reject;
  });
  createInterface({ input: child.stdout, crlfDelay: Infinity })
    .on('line', line => {
      let msg;
      try { msg = JSON.parse(line); } catch { msg = { type: 'invalid' }; }
      if (msg.type === 'ready' && !publicKey) {
        publicKey = msg.publicKey;
        signalReady(publicKey);
      } else if (waiting) {
        const p = waiting;
        waiting = null;
        if (msg.type === 'receipt' && msg.attemptId === p.attemptId &&
            /^[a-f0-9]{64}$/.test(msg.digest) &&
            Number.isSafeInteger(msg.sequence) && msg.sequence > 0) {
          p.resolve(msg);
        } else {
          p.reject(new Error('M1h signer rejected or corrupted request'));
        }
      }
    });
  child.on('error', () => {
    if (!publicKey) failReady(new Error('M1h witness start failure'));
    if (waiting) { waiting.reject(new Error('M1h signer unavailable')); waiting=null; }
    alive = false;
  });
  child.on('exit', () => {
    if (!publicKey) failReady(new Error('M1h witness exited before ready'));
    if (waiting) { waiting.reject(new Error('M1h signer exited')); waiting=null; }
    alive = false;
  });
  const key = await ready;
  assert.ok(typeof key === 'string' && /^[A-Za-z0-9+/=]{40,500}$/.test(key));
  return Object.freeze({
    publicKey: key,
    async prepare(entry) {
      if (!alive || waiting || !validV4.test(entry.attemptId))
        throw new Error('M1h signer not available for write');
      return new Promise((resolve, reject) => {
        waiting = { resolve, reject, attemptId: entry.attemptId };
        child.stdin.write(JSON.stringify({ type: 'prepare', entry }) + '\n',
          err => {
            if (err && waiting) {
              waiting = null;
              reject(new Error('M1h failed to submit intent'));
            }
          });
      });
    },
    async stop() {
      if (!alive) return;
      await new Promise((resolve, reject) => {
        child.once('exit', resolve);
        child.stdin.end();
        child.once('error', reject);
      });
    },
  });
}
export function runOffline(assert, path, key, count) {
  const command = ['node', WORKER, 'verify', path, key, String(count)];
  const result = Bun.spawnSync(command, {
    env: witnessEnv, stdout: 'pipe', stderr: 'pipe',
  });
  if (result.exitCode !== 0) return null;
  const value = JSON.parse(utf8(result.stdout));
  assert.equal(value.type, 'verified');
  return value;
}
function dbEvidence(assert, project, attemptId) {
  assert.ok(/^m1h-[a-z-]+$/.test(project));
  assert.ok(validV4.test(attemptId));
  // Fixed, test-only escaped SQL literals. All fields are validated above.
  return realPgFixture(assert,
    "SELECT (SELECT COUNT(*) FROM saas_m1_private.projects WHERE " +
      "tenant_id='demo-north' AND project_id='" + project + "')::TEXT || ':' || " +
    "(SELECT COUNT(*) FROM saas_m1_private.project_write_audit_outbox WHERE " +
      "tenant_id='demo-north' AND project_id='" + project + "')::TEXT || ':' || " +
    "(SELECT COUNT(*) FROM saas_m1_private.project_attempt_bindings b " +
      "JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id " +
      "WHERE b.attempt_id='" + attemptId + "'::UUID AND a.tenant_id='demo-north' " +
      "AND a.project_id='" + project + "' AND a.actor_id='actor-north' " +
      "AND a.operation='create' AND a.project_version=1)::TEXT"
  );
}

export async function verifyM1h({
  assert, makeDriver, boundary, command, northToken, northScope,
}) {
  if (process.env.GITHUB_ACTIONS !== 'true' ||
      process.env.SAAS_EPHEMERAL_M1_PG_CI !== 'true' ||
      process.env.SAAS_EPHEMERAL_M1G_ATTEMPT_CI !== 'true' ||
      process.env.SAAS_EPHEMERAL_M1H_INTENT_CI !== 'true' ||
      process.env.PGHOST !== '127.0.0.1' ||
      process.env.PGPORT !== '5432' ||
      process.env.PGDATABASE !== 'saas_ephemeral_test' ||
      process.env.NODE_ENV === 'production' ||
      process.env.RAILWAY_PROJECT_ID || process.env.RAILWAY_ENVIRONMENT) {
    throw new Error('M1h proof requires isolated M1g disposable PG16 CI');
  }
  console.info('STEP M1h: isolated signed fsync pre-COMMIT intents (not external WORM)');
  const suffix = crypto.randomUUID();
  const path = '/tmp/saas-m1h-intent-' + suffix + '.jsonl';
  const witness = await startWitness(assert, path);
  const issued = [];
  const prepareAndWrite = native => boundary({
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
      // MUST be acknowledged only AFTER journal fsync BEFORE any PG DML.
      const receipt = await witness.prepare(entry);
      assert.equal(receipt.attemptId, attemptId);
      issued.push(entry);
      return native.execute({ ...input, attemptId });
    },
  });

  // Case 1: PG COMMIT succeeded, caller loses ACK. The signer has a
  // PRE-COMMIT receipt, while another PG observer sees 1/1/1. No retry.
  const committed = makeDriver({ attemptTagging: true, dropAckAfterCommit: true });
  try {
    const result = await prepareAndWrite(committed)(
      command('create', northToken, 'm1h-ack-lost'));
    assert.equal(result.status, 503);
    assert.equal(committed.stats().poisoned, true);
    assert.equal(committed.stats().reservations, 1);
    assert.equal(committed.stats().commitAcks, 0);
  } finally {
    await committed.close();
  }

  // Case 2: separate privileged fixture terminates the exact Bun.SQL
  // backend after project+audit DML but BEFORE COMMIT. The PRE-COMMIT
  // intent survives, and this PG transaction has 0/0/0. A 503 is not
  // interpreted as an authorized retry.
  let lostPid = null;
  const physicallyLost = makeDriver({
    attemptTagging: true,
    beforeCommit({ backendPid }) {
      assert.ok(Number.isSafeInteger(backendPid) && backendPid>0);
      lostPid = backendPid;
      assert.equal(realPgFixture(assert,
        "SELECT CASE WHEN pg_terminate_backend(" + backendPid + ") " +
        "THEN 'terminated' ELSE 'missing' END"), 'terminated');
    },
  });
  try {
    const result = await prepareAndWrite(physicallyLost)(
      command('create', northToken, 'm1h-precommit-loss'));
    assert.equal(result.status, 503);
    assert.equal(physicallyLost.stats().poisoned, true);
    assert.equal(physicallyLost.stats().reservations, 1);
    assert.equal(physicallyLost.stats().commitAcks, 0);
  } finally {
    await physicallyLost.close();
  }
  assert.ok(lostPid && lostPid>0);
  assert.equal(realPgFixture(assert,
    "SELECT COUNT(*) FROM pg_stat_activity WHERE pid=" + lostPid), '0');

  assert.equal(issued.length, 2);
  assert.ok(issued.every(x=>validV4.test(x.attemptId)));
  assert.notEqual(issued[0].attemptId, issued[1].attemptId);

  // Duplicate signing request cannot overwrite or append a forged
  // attempt. The two registered receipts have a consecutive hash chain.
  await assert.rejects(
    () => witness.prepare(issued[0]), /M1h signer rejected/
  );
  await witness.stop();

  // Different NO-PG-credentials process verifies a transient pinned public
  // Ed25519 key, each signature, chained hashes and observed count.
  const verified = runOffline(assert, path, witness.publicKey, 2);
  assert.ok(verified && verified.count === 2);
  assert.deepEqual(verified.attempts, issued);
  assert.equal(dbEvidence(assert, 'm1h-ack-lost', issued[0].attemptId), '1:1:1');
  assert.equal(dbEvidence(assert, 'm1h-precommit-loss', issued[1].attemptId), '0:0:0');

  // The local journal cannot survive a malicious shared-host rollback
  // without a separately pinned expected high-water; the following
  // negative checks explicitly provide the transient expected count.
  const original = await readFile(path, 'utf8');
  const tampered = '/tmp/saas-m1h-tampered-' + suffix + '.jsonl';
  const truncated = '/tmp/saas-m1h-truncated-' + suffix + '.jsonl';
  assert.ok(original.includes('"projectId":"m1h-ack-lost"'));
  await writeFile(tampered,
    original.replace('"projectId":"m1h-ack-lost"', '"projectId":"m1h-replaced"'),
    { flag: 'wx', mode: 0o600 });
  await writeFile(truncated, original.split('\n').slice(0, 1).join('\n')+'\n',
    { flag: 'wx', mode: 0o600 });
  assert.equal(runOffline(assert, tampered, witness.publicKey, 2), null,
    'M1h tampered Ed25519 record must fail closed');
  assert.equal(runOffline(assert, truncated, witness.publicKey, 2), null,
    'M1h truncated journal must fail expected high-water');
  const otherKey = generateKeyPairSync('ed25519').publicKey
    .export({ format: 'der', type: 'spki' }).toString('base64');
  assert.equal(runOffline(assert, path, otherKey, 2), null,
    'M1h replacement witness signer must fail pinned verification');

  // With the intent signer stopped, no further PG write may be reserved.
  const notExecuted = makeDriver({ attemptTagging: true });
  try {
    const result = await prepareAndWrite(notExecuted)(
      command('create', northToken, 'm1h-signer-dead'));
    assert.equal(result.status, 503);
    assert.equal(notExecuted.stats().reservations, 0);
  } finally {
    await notExecuted.close();
  }
  const observer = makeDriver();
  try {
    assert.equal((await observer.read(northScope, 'm1h-signer-dead')).length, 0);
  } finally {
    await observer.close();
  }
  assert.equal(realPgFixture(assert,
    "SELECT (SELECT COUNT(*) FROM saas_m1_private.projects " +
    "WHERE project_id='m1h-signer-dead')::TEXT || ':' || " +
    "(SELECT COUNT(*) FROM saas_m1_private.project_write_audit_outbox " +
    "WHERE project_id='m1h-signer-dead')::TEXT"), '0:0');

  console.info(
    'PASS M1h: separate fsynced Ed25519 PRE-COMMIT intent, signed chain ' +
    'and offline verification; 503 COMMITTED 1/1/1 vs precommit loss 0/0/0; ' +
    'tamper/truncate/key swap and dead signer DENY, NO retry/WORM/production'
  );
}
