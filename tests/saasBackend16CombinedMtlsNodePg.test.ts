import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const script=readFileSync(new URL(
  '../scripts/saas-staging/verify-backend16-combined-mtls-nodepg-ci.ts',
  import.meta.url),'utf8');
const shell=readFileSync(new URL(
  '../scripts/saas-staging/verify-backend16-exact-session-pg16.sh',
  import.meta.url),'utf8');

test('combined Backend16 mTLS/PG16 runner is disposable and one-process',()=>{
  for(const value of [
    "e.GITHUB_ACTIONS!=='true'",
    "e.SAAS_B16_COMBINED_MTLS_PG_CI!=='true'",
    "e.SAAS_B16_BROKER_MTLS_CI!=='true'",
    "e.SAAS_B16_NODEPG_PHYSICAL_CI!=='true'",
    "e.PGHOST!=='127.0.0.1'",
    "e.PGDATABASE!=='saas_ephemeral_test'",
    "e.NODE_TLS_REJECT_UNAUTHORIZED==='0'",
    "'postgres:16.6'",
    "requestCert:true,rejectUnauthorized:true",
    "createBackend16DisposableCiMtlsSecretReader",
    "createBackend16StagingVersionedPrincipalVault",
    "createBackend16DisposableCiNodePgPhysicalPool",
    "createBackend16ExactSqlReadPort",
    "read(a,tb,fresh())",
    "read(b,ta,fresh())",
    "assert.equal(brokerCalls,4",
    "SELECT ssl,version FROM pg_stat_ssl WHERE pid=$1",
    "await gone(pid)",
    "e.SAAS_B16_BROKER_MTLS_CI='false'",
    "releaseReply?.()",
    "await noLogin(A)",
    "PASS Backend16 combined mTLS broker vault Node PostgreSQL16 TLS tenant RLS",
  ])assert.ok(script.includes(value),value);
  assert.doesNotMatch(script,/DATABASE_PUBLIC_URL|Bun\.serve|pg_terminate_backend/);
  assert.ok(shell.includes('verify-backend16-combined-mtls-nodepg-ci.ts'));
  assert.ok(shell.indexOf('verify-backend16-combined-mtls-nodepg-ci.ts')<
    shell.indexOf('verify-backend16-native-pg-tls-ci.ts'),
    'do not replace or bypass the native Bun SQL TLS RED regression');
});
test('real broker only serves exact current version and client-authenticated TLS',()=>{
  for(const value of [
    "createHash('sha256').update(peer.raw).digest('hex')===clientPin",
    "allowed.get(req.url??'')",
    "req.method!=='GET'",
    "username:entry.login,password:credentials.get(entry.login)",
    "version:entry.version,expiresAtMs:Date.now()+120_000",
    "'Content-Type':'application/json'",
    "'Cache-Control':'no-store'",
    "'Content-Length':Buffer.byteLength(body)",
    "assert.equal(authorizedRequests,brokerCalls)",
  ])assert.ok(script.includes(value),value);
  assert.ok(!script.includes('DATABASE_URL'));
});
