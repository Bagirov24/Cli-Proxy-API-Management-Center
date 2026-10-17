import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL(
  '../scripts/saas-staging/backend16-pg-tls-peer-observation.ts',
  import.meta.url),'utf8');

test('literal PostgreSQL SSLRequest is the ONLY non-TLS application bytes',()=>{
  assert.match(source,/Buffer\.from\(\[0,0,0,8,4,210,22,47\]\)/);
  assert.match(source,/tcp\.write\(SSL_REQUEST\)/);
  assert.match(source,/reply\.length!==1\|\|reply\[0\]!==83/);
  assert.equal((source.match(/\.write\(/g)||[]).length,1);
  assert.doesNotMatch(source,/pg\.Client|Bun\.SQL|\.query\(|\.unsafe\(/);
  assert.doesNotMatch(source,/StartupMessage\s*=\s*Buffer|password\s*:\s*\S|username\s*:\s*\S|DATABASE_URL|DATABASE_PUBLIC_URL/);
});

test('no-credential staging-only gate refuses production/CI or disabled',()=>{
  for(const name of [
    'RAILWAY_PROJECT_ID','RAILWAY_ENVIRONMENT_ID',
    'RAILWAY_ENVIRONMENT_NAME','RAILWAY_SERVICE_NAME',
    'SAAS_B16_TLS_PEER_PROBE_EXPLICIT_ENABLE','GITHUB_ACTIONS',
    "const SERVICE='saas-b16-pg-tls-peer-probe'",
    "const HOST='postgres.railway.internal'",
    "const PORT=5432",
  ])assert.ok(source.includes(name),name);
  assert.match(source,/env\.RAILWAY_ENVIRONMENT_NAME!=='staging'/);
  assert.match(source,/env\.SAAS_B16_TLS_PEER_PROBE_EXPLICIT_ENABLE!=='true'/);
  assert.doesNotMatch(source,/Bun\.serve|createServer\(|\.listen\(|cronSchedule\s*:|setInterval\s*\(/);
});

test('unverified certificate inspection never asserts trusted server',()=>{
  assert.match(source,/rejectUnauthorized:false/);
  assert.match(source,/unverifiedChain:true/);
  assert.match(source,/noCredentialsOrSql:true/);
  assert.match(source,/B16_TLS_PEER_OBSERVED_CERTIFICATE_ONLY_NO_SQL/);
  assert.match(source,/B16_TLS_PEER_HOST_OR_VALIDITY_MISMATCH_STOP_RUNTIME/);
  assert.match(source,/B16_TLS_PEER_HOST_AND_VALIDITY_OBSERVED_CA_UNAPPROVED/);
  assert.match(source,/leaf\.checkHost\(HOST,\{subject:'never'\}\)/);
  assert.match(source,/tlsSocket\.getPeerCertificate\(true\)/);
  assert.match(source,/leafDerSha256:sha\(leaf\.raw\)/);
  assert.match(source,/MAX_CERT_BYTES/);
  assert.match(source,/setTimeout\(\(\)=>fail\(\),MAX_WAIT_MS\)/);
  assert.match(source,/tlsSocket\?\.destroy\(\)/);
  assert.match(source,/tcp\.destroy\(\)/);
  assert.doesNotMatch(source,/PASS_BACKEND16_PG_TLS_TRUSTED|TLS_VERIFIED_FULL/);
});

test('public certificate evidence is field-limited with no PEM logging',()=>{
  const record=source.slice(
    source.indexOf("finish(Object.freeze({"),
    source.indexOf("}));",source.indexOf("finish(Object.freeze({"))+4);
  assert.ok(record.includes("leafDnsSanMatchesPrivateHostname:sanMatch"));
  assert.ok(record.includes("leafNotAfterUtc:new Date(notAfter).toISOString()"));
  assert.ok(record.includes("noCredentialsOrSql:true"));
  assert.doesNotMatch(record,/password|token|userName|subject|issuerPem|privateKey/i);
  assert.doesNotMatch(source,/console\.(?:log|info|error)\((?:cert|leaf|tcp|tlsSocket|process\.env)/);
});
