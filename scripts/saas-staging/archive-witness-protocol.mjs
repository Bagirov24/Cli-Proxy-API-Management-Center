#!/usr/bin/env node
// Stage 2G.4d.7j: detached, CI-only proof candidate. NO GC, API or delivery.
// Witness process is intentionally isolated from PostgreSQL credentials.
import {
  createHash, createPrivateKey, createPublicKey,
  generateKeyPairSync, sign as edSign, verify as edVerify,
} from 'node:crypto';
import { readFileSync, writeFileSync, chmodSync, existsSync } from 'node:fs';

const PROTOCOL = 'saas-synthetic-uuid-witness-v1';
const AUDIENCE = 'ephemeral-pg16-proof-only';
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX = /^[0-9a-f]{64}$/;
const LIMIT = 16384;
const ownKeys = (x, keys) => x && typeof x === 'object' &&
  !Array.isArray(x) && Object.keys(x).sort().join(',') === keys.slice().sort().join(',');
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const check = (condition, why) => { if (!condition) throw new Error(why); };
const loadJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const saveJson = (p, obj) => writeFileSync(p, JSON.stringify(obj) + '\n', { flag: 'wx', mode: 0o600 });

function assertSet(arr, name) {
  check(Array.isArray(arr) && arr.length <= LIMIT, 'Invalid ' + name + ' array');
  let prior = '';
  for (const item of arr) {
    check(typeof item === 'string' && HEX.test(item) && item > prior,
      'Noncanonical, duplicate, or malformed ' + name + ' commitment');
    prior = item;
  }
}
export function projectionFromSql(sqlOutput) {
  check(typeof sqlOutput === 'string' && sqlOutput.length < 2_000_000,
    'Invalid SQL projection size');
  const sets = { issued: new Set(), producer: new Set() };
  for (const line of sqlOutput.trim().split('\n')) {
    if (!line) continue;
    const fields = line.split('|');
    check(fields.length === 2 && Object.hasOwn(sets, fields[0]) &&
      UUID4.test(fields[1]), 'Invalid non-payload PostgreSQL projection');
    const commitment = sha256(PROTOCOL + '\0' + fields[0] + '\0' + fields[1]);
    check(!sets[fields[0]].has(commitment), 'Duplicate operation identity in projection');
    sets[fields[0]].add(commitment);
    check(sets.issued.size <= LIMIT && sets.producer.size <= LIMIT,
      'Projection capacity exceeded');
  }
  const issued = [...sets.issued].sort();
  const producer = [...sets.producer].sort();
  return {
    protocol: PROTOCOL + '-commitments',
    issued, producer,
    issuedCount: issued.length,
    producerCount: producer.length,
  };
}
export function canonicalProjection(input) {
  check(ownKeys(input,
    ['protocol','issued','producer','issuedCount','producerCount']),
    'Unknown projection fields');
  check(input.protocol === PROTOCOL + '-commitments', 'Wrong projection protocol');
  assertSet(input.issued, 'issued');
  assertSet(input.producer, 'producer');
  check(Number.isSafeInteger(input.issuedCount) &&
    input.issuedCount === input.issued.length &&
    Number.isSafeInteger(input.producerCount) &&
    input.producerCount === input.producer.length,
    'Projection cardinality mismatch');
  return {
    protocol: PROTOCOL + '-commitments',
    issued: input.issued, producer: input.producer,
    issuedCount: input.issuedCount,
    producerCount: input.producerCount,
  };
}
function containsAll(current, older, name) {
  const lookup = new Set(current[name]);
  for (const commitment of older[name]) {
    check(lookup.has(commitment),
      'Rollback, missing UUID, or incomplete restore in ' + name);
  }
}
function assertCoverage(current, earlier) {
  for (const name of ['issued','producer']) containsAll(current, earlier, name);
}
function canonicalPayload(value) {
  check(ownKeys(value, ['protocol','audience','sequence','previous','projectionRoot','projection']),
    'Unexpected witness payload fields');
  check(value.protocol === PROTOCOL && value.audience === AUDIENCE,
    'Wrong witness protocol or audience');
  check(Number.isSafeInteger(value.sequence) && value.sequence >= 1,
    'Bad witness sequence');
  check(value.previous === null || (typeof value.previous === 'string' && HEX.test(value.previous)),
    'Malformed previous checkpoint digest');
  const projection = canonicalProjection(value.projection);
  check(typeof value.projectionRoot === 'string' &&
    value.projectionRoot === sha256(JSON.stringify(projection)),
    'Projection digest mismatch');
  return {
    protocol: PROTOCOL, audience: AUDIENCE, sequence: value.sequence,
    previous: value.previous, projectionRoot: value.projectionRoot,
    projection,
  };
}
function keyHash(publicKey) {
  return sha256(createPublicKey(publicKey).export({ format:'der', type:'spki' }));
}
export function envelopeDigest(envelope) {
  return sha256(JSON.stringify(envelope));
}
export function verifyEnvelope(envelope, publicPem) {
  check(ownKeys(envelope, ['payload','algorithm','keyFingerprint','signature']),
    'Unexpected attestation fields');
  check(envelope.algorithm === 'Ed25519' &&
    envelope.keyFingerprint === keyHash(publicPem),
    'Wrong witness algorithm or unpinned trust root');
  const payload = canonicalPayload(envelope.payload);
  check(typeof envelope.signature === 'string' &&
    /^[A-Za-z0-9_-]{80,120}$/.test(envelope.signature),
    'Malformed detached signature');
  const encoded = Buffer.from(PROTOCOL + '\n' + JSON.stringify(payload));
  const signature = Buffer.from(envelope.signature, 'base64url');
  check(signature.length === 64 && edVerify(null, encoded, publicPem, signature),
    'Detached witness signature invalid');
  return payload;
}
export function verifyCheckpoint(envelope, pinnedPublicPem, trustedHead, restored, previous) {
  const payload = verifyEnvelope(envelope, pinnedPublicPem);
  check(ownKeys(trustedHead, ['sequence','digest']) &&
    trustedHead.sequence === payload.sequence &&
    trustedHead.digest === envelopeDigest(envelope),
    'Stale, forked, or replaced external trusted checkpoint');
  if (previous === null) {
    check(payload.sequence === 1 && payload.previous === null,
      'Witness chain missing predecessor');
  } else {
    const priorPayload = verifyEnvelope(previous, pinnedPublicPem);
    check(payload.sequence === priorPayload.sequence + 1 &&
      payload.previous === envelopeDigest(previous),
      'Witness predecessor mismatch or broken sequence');
    assertCoverage(payload.projection, priorPayload.projection);
  }
  assertCoverage(canonicalProjection(restored), payload.projection);
  return { sequence:payload.sequence, digest:envelopeDigest(envelope),
    gcPermitted:false };
}

function requireOfflineWitness() {
  check(process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE === 'true' &&
    process.env.GITHUB_ACTIONS === 'true' &&
    !process.env.PGHOST && !process.env.PGUSER &&
    !process.env.PGPASSWORD && !process.env.PGDATABASE &&
    !process.env.RAILWAY_ENVIRONMENT && !process.env.RAILWAY_PROJECT_ID,
    'Witness must be isolated from database credentials and production');
}
function readKey(file) {
  const data = readFileSync(file, 'utf8');
  check(data.length < 16000, 'Oversized key material');
  return data;
}
function signCheckpoint(projection, previous, privatePem, publicPem) {
  const candidate = canonicalProjection(projection);
  let seq = 1, prior = null;
  if (previous !== null) {
    const signed = verifyEnvelope(previous, publicPem);
    assertCoverage(candidate, signed.projection);
    seq = signed.sequence + 1;
    prior = envelopeDigest(previous);
  }
  const payload = canonicalPayload({
    protocol:PROTOCOL, audience:AUDIENCE, sequence:seq,
    previous:prior, projectionRoot:sha256(JSON.stringify(candidate)),
    projection:candidate,
  });
  const signature = edSign(null,
    Buffer.from(PROTOCOL + '\n' + JSON.stringify(payload)),
    createPrivateKey(privatePem)).toString('base64url');
  return {
    payload, algorithm:'Ed25519', keyFingerprint:keyHash(publicPem),
    signature,
  };
}
function runCli() {
  requireOfflineWitness();
  const [cmd, ...args] = process.argv.slice(2);
  if (cmd === 'keygen') {
    check(args.length === 2 && !existsSync(args[0]) && !existsSync(args[1]),
      'keygen requires new private/public paths');
    const pair = generateKeyPairSync('ed25519');
    writeFileSync(args[0], pair.privateKey.export({type:'pkcs8',format:'pem'}),
      {flag:'wx', mode:0o600});
    chmodSync(args[0], 0o600);
    writeFileSync(args[1], pair.publicKey.export({type:'spki',format:'pem'}),
      {flag:'wx', mode:0o600});
  } else if (cmd === 'sign') {
    check(args.length === 5, 'sign: private public projection predecessor-or-dash output');
    const [privatePath,publicPath,projectionPath,previousPath,output] = args;
    const prior = previousPath === '-' ? null : loadJson(previousPath);
    saveJson(output, signCheckpoint(loadJson(projectionPath), prior,
      readKey(privatePath), readKey(publicPath)));
  } else if (cmd === 'verify') {
    check(args.length === 5,
      'verify: public attestation predecessor-or-dash trusted-head observed-projection');
    const [publicPath,envelopePath,previousPath,headPath,currentPath] = args;
    const prior = previousPath === '-' ? null : loadJson(previousPath);
    const result = verifyCheckpoint(loadJson(envelopePath), readKey(publicPath),
      loadJson(headPath), loadJson(currentPath), prior);
    check(result.gcPermitted === false, 'Never authorize GC');
    process.stdout.write('PASS: offline pinned signed witness checkpoint ' + result.sequence +
      ', UUID coverage holds; GC NOT PERMITTED\n');
  } else {
    throw new Error('Expected keygen, sign, or verify command');
  }
}
if (process.argv[1] && process.argv[1].endsWith('archive-witness-protocol.mjs')) {
  try { runCli(); }
  catch (err) {
    process.stderr.write('WITNESS DENIED: ' + (err?.message || String(err)) + '\n');
    process.exitCode = 1;
  }
}
