import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createBackend16DisposableCiNodePgPhysicalPool}
  from '../src/features/saasBlueprint/controlApi/server/backend16DisposableNodePgPhysicalPool.ts';

const filename=new URL(
  '../src/features/saasBlueprint/controlApi/server/backend16DisposableNodePgPhysicalPool.ts',
  import.meta.url);
const source=readFileSync(filename,'utf8');
const vault={async readPrincipal(login:string){
  return {username:login,password:'x'.repeat(64)};
}};
class ClientFixture{
  constructor(_opts:Readonly<Record<string,unknown>>){}
  async connect(){throw Error('must never construct outside disposable CI');}
  async query(_sql:string,_params:readonly string[]=[]){
    return {rows:[]};
  }
  async end(){}
  on(_ev:'error',_cb:()=>void){}
}

test('Node PG physical factory cannot run outside disposable GitHub PG16',()=>{
  assert.throws(()=>createBackend16DisposableCiNodePgPhysicalPool(
    vault,null as never,ClientFixture),
    /Backend16 Node PostgreSQL physical TLS unavailable/);
});
test('Node PG uses reviewed TLS callback, no plaintext or shared LOGIN',()=>{
  for(const required of [
    "e.GITHUB_ACTIONS!=='true'",
    "e.SAAS_B16_EPHEMERAL_CI!=='true'",
    "e.SAAS_B16_NODEPG_PHYSICAL_CI!=='true'",
    "e.PGHOST!=='127.0.0.1'",
    "e.PGDATABASE!=='saas_ephemeral_test'",
    "e.NODE_TLS_REJECT_UNAUTHORIZED==='0'",
    'backend16IsApprovedStagingPgTlsTrust(trust)',
    "servername:HOST,rejectUnauthorized:true",
    'checkServerIdentity:(hostname:string,cert:unknown)',
    'return trust.checkServerIdentity(hostname,cert)',
    'vault.readPrincipal(login,signal)',
    'credential.username!==login',
    'client.connection?.stream?.destroy()',
    'if(stopped)return;',
    "client.on('error',()=>{quarantine('socket-uncertain');});",
    'quarantine(\'query-uncertain\')',
    'AbortSignal.timeout(6500)',
    'SQL.exact,4',
    'SQL.commit,0',
    "application_name:'b16-nodepg-exact-ci'",
    "options:'-c saas.staging_only=true'",
  ])assert.ok(source.includes(required),required);
  assert.doesNotMatch(source,/Bun\.serve|createServer\(|\.listen\(|DATABASE_PUBLIC_URL/);
  assert.doesNotMatch(source,/tls:'require'|rejectUnauthorized:false/);
  assert.doesNotMatch(source,/SET ROLE|CREATE ROLE|ALTER ROLE|DROP ROLE/i);
});
test('CI PG16 proof uses a real guarded two-principal mTLS broker',()=>{
  const runner=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-nodepg-exact-pg16-ci.ts',
    import.meta.url),'utf8');
  const broker=readFileSync(new URL(
    '../scripts/saas-staging/backend16-nodepg-synthetic-mtls-broker-ci.ts',
    import.meta.url),'utf8');
  const shell=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-exact-session-pg16.sh',
    import.meta.url),'utf8');
  for(const marker of [
    'createBackend16DisposableCiMtlsSecretReader',
    'createBackend16StagingVersionedPrincipalVault',
    'startSyntheticBackend16MtlsBroker',
    'B16_NODEPG_COMBINED_MTLS_VERSIONED_TLS_RLS_PASS',
    'B16_NODEPG_MTLS_WRONG_VERSION_AND_EXPIRED_PREAUTH_DENY',
    'B16_NODEPG_MTLS_REVOKED_IN_FLIGHT_PREAUTH_DENY',
    'B16_NODEPG_EXACT_RESTORED_TLS_PRE_LOCK_PASS',
    'B16_NODEPG_ASYNC_SOCKET_ERROR_QUARANTINE_PID_DEATH_PASS',
    "process.env.SAAS_B16_BROKER_MTLS_CI='false'",
    'await noLogin(A)',
    'activeBroker.close()',
  ])assert.ok(runner.includes(marker),marker);
  for(const marker of [
    "e.GITHUB_ACTIONS!=='true'",
    "e.SAAS_B16_BROKER_MTLS_CI!=='true'",
    "server.listen(0,'127.0.0.1',resolve)",
    "requestCert:true,rejectUnauthorized:true",
    "approvedClient=trust.approvedClientCertDerSha256",
    "req.method!=='GET'",
    "mode==='wrong-version'",
    "mode==='expired'",
    'releaseDeferred()',
    "rmSync(dir,{recursive:true,force:true})",
  ])assert.ok(broker.includes(marker),marker);
  assert.ok(shell.includes('SAAS_B16_BROKER_MTLS_CI=true'));
  assert.ok(shell.includes(
    'PASS Backend16 Node PG synthetic mTLS broker vault PG16 RLS full chain'));
  assert.doesNotMatch(broker,/DATABASE_PUBLIC_URL|Bun\.serve|\.listen\(\s*443/);
  assert.doesNotMatch(runner,/retry\s*\(|DATABASE_PUBLIC_URL/);
});

test('adapter is neither a production staging factory nor a packaged dependency',()=>{
  assert.ok(source.includes('createBackend16DisposableCiNodePgPhysicalPool'));
  assert.doesNotMatch(source,/createBackend16StagingNodePgPhysicalPool/);
  assert.doesNotMatch(source,/import\s+.*\s+from\s+['"]pg['"]/);
  assert.ok(source.includes('const poison=discard||stopped||!steps.finished()'));
});
