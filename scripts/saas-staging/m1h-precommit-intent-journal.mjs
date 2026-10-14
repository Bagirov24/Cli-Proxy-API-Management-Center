#!/usr/bin/env node
/**
 * M1h — disposable GitHub CI signed PRE-COMMIT intent journal.
 *
 * A separate local Node process holds an ephemeral Ed25519 private key and
 * fsyncs an append-only (application contract, NOT OS WORM) JSONL journal
 * BEFORE returning the prepare receipt. The signer has NO PG credentials.
 *
 * This is deliberately NOT an independent trust domain, remote witness,
 * production signer, durable human receipt, retry/idempotency authority,
 * or evidence that PostgreSQL committed a transaction.
 */
import assert from 'node:assert/strict';
import {
  constants, openSync, closeSync, writeSync, fsyncSync, readFileSync, statSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { createInterface } from 'node:readline';
import {
  generateKeyPairSync, createHash, createPublicKey, sign, verify,
} from 'node:crypto';

const ciOnly = process.env.GITHUB_ACTIONS === 'true' &&
  process.env.SAAS_EPHEMERAL_M1H_INTENT_CI === 'true' &&
  process.env.PGHOST === '127.0.0.1' &&
  process.env.PGPORT === '5432' &&
  process.env.PGDATABASE === 'saas_ephemeral_test' &&
  process.env.NODE_ENV !== 'production' &&
  !process.env.RAILWAY_PROJECT_ID &&
  !process.env.RAILWAY_ENVIRONMENT;
if (!ciOnly) throw new Error('M1h journal denied outside disposable GitHub PG16');
const [mode, journalPath, publicKeyB64, expectedCountRaw] = process.argv.slice(2);
if (!['writer', 'verify'].includes(mode) ||
    !/^\/tmp\/saas-m1h-(?:intent|tampered|truncated)-[0-9a-f-]{36}\.jsonl$/.test(journalPath || '')) {
  throw new Error('M1h journal requires fixed disposable /tmp fixture path');
}
const safeId = /^[A-Za-z0-9_-]{1,64}$/;
const safeActor = /^[A-Za-z0-9_-]{1,128}$/;
const v4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ZERO = '0'.repeat(64);
function validateEntry(entry) {
  return entry && typeof entry === 'object' &&
    Object.keys(entry).sort().join(',') ===
       'actorId,attemptId,expectedVersion,operation,projectId,tenantId' &&
    v4.test(entry.attemptId) && safeActor.test(entry.actorId) &&
    safeId.test(entry.tenantId) && safeId.test(entry.projectId) &&
    ['create', 'rename', 'disable'].includes(entry.operation) &&
    (entry.operation === 'create'
      ? entry.expectedVersion === null
      : Number.isSafeInteger(entry.expectedVersion) && entry.expectedVersion >= 1);
}
const canonical = row => JSON.stringify({
  sequence: row.sequence, previousDigest: row.previousDigest, entry: {
    attemptId: row.entry.attemptId,
    actorId: row.entry.actorId, tenantId: row.entry.tenantId,
    projectId: row.entry.projectId, operation: row.entry.operation,
    expectedVersion: row.entry.expectedVersion,
  },
});
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function output(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

if (mode === 'writer') {
  assert.equal(publicKeyB64, undefined);
  const fd = openSync(
    journalPath, constants.O_CREAT | constants.O_EXCL |
      constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600
  );
  // The file name, then each append, has a local fsync boundary.
  const dirfd = openSync(dirname(journalPath), constants.O_RDONLY);
  fsyncSync(dirfd);
  closeSync(dirfd);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicDer = publicKey.export({ type: 'spki', format: 'der' });
  output({ type: 'ready', publicKey: publicDer.toString('base64') });
  let sequence = 0;
  let previousDigest = ZERO;
  const seen = new Set();
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  try {
    for await (const line of input) {
      let entry;
      try {
        const packet = JSON.parse(line);
        if (!packet || packet.type !== 'prepare' ||
            !validateEntry(packet.entry) ||
            seen.has(packet.entry.attemptId)) {
          throw new Error('rejected');
        }
        entry = packet.entry;
        const base = { sequence: sequence + 1, previousDigest, entry };
        const digest = sha256(canonical(base));
        const signature = sign(null, Buffer.from(digest, 'hex'), privateKey)
          .toString('base64');
        writeSync(fd, JSON.stringify({ ...base, digest, signature }) + '\n');
        fsyncSync(fd); // MUST happen BEFORE sending receipt to PG writer.
        sequence++;
        previousDigest = digest;
        seen.add(entry.attemptId);
        output({ type: 'receipt', attemptId: entry.attemptId,
          sequence, digest, signature });
      } catch {
        output({ type: 'denied' }); // never log raw inputs/tokens
      }
    }
  } finally {
    closeSync(fd);
  }
} else {
  if (!/^[A-Za-z0-9+/=]{40,500}$/.test(publicKeyB64 || '') ||
      !/^[1-9][0-9]{0,3}$/.test(expectedCountRaw || '')) {
    throw new Error('M1h verifier requires pinned public key and count');
  }
  const expectedCount = Number(expectedCountRaw);
  const file = statSync(journalPath);
  assert.ok(file.isFile() && file.size > 0 && file.size < 1024 * 1024,
    'M1h bounded regular journal only');
  const raw = readFileSync(journalPath, 'utf8');
  assert.ok(raw.endsWith('\n'), 'M1h cannot accept torn final record');
  const records = raw.trimEnd().split('\n').map(line => JSON.parse(line));
  assert.equal(records.length, expectedCount,
    'M1h high-water mismatch: rollback/truncation must stop');
  const pinned = createPublicKey({
    key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki',
  });
  let prior = ZERO;
  const seen = new Set();
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    assert.ok(validateEntry(r.entry), 'M1h invalid signed intent content');
    assert.equal(r.sequence, i + 1, 'M1h sequence mismatch');
    assert.equal(r.previousDigest, prior, 'M1h chained intent mismatch');
    assert.ok(!seen.has(r.entry.attemptId), 'M1h duplicate server attempt');
    assert.ok(/^[a-f0-9]{64}$/.test(r.digest), 'M1h invalid digest');
    const expected = sha256(canonical(r));
    assert.equal(r.digest, expected, 'M1h tampered body');
    assert.equal(
      verify(null, Buffer.from(r.digest, 'hex'), pinned,
        Buffer.from(r.signature, 'base64')),
      true, 'M1h signer mismatch'
    );
    seen.add(r.entry.attemptId);
    prior = r.digest;
  }
  output({ type: 'verified', count: records.length,
    highWater: prior, attempts: records.map(r => r.entry) });
}
